-- Per-thread pattern stage. filtering.lua passes `local M = <match.lua>` followed by this file to
-- LuaFFIPerThreadAction: every dnsdist thread runs it in its own Lua state, without the global
-- Lua lock and without the main config's globals (setupLuaFFIPerThreadContext at the
-- dnsdist/pins.env version: setupLuaVars, logging, the FFI cdefs only; no KVS bindings).
-- Plain-table values are read by C++ actions into tags.
--
-- It computes what dnsdohPatternStage (patterns.lua) computes, in the same order, from the
-- pattern rows held in memory (`#pf`, compile emit.rs thread_rows). It hands a query to that
-- global stage (tag px=1) for the root name, an unusual name whose host prefix has more than
-- HMAX labels, and any Lua error (counted in dnsdoh-filter-thread-fallbacks; filtering.lua's
-- wrapper does the same for every query if this chunk fails to load). One action object serves every step (one per-thread state,
-- keyed by the action's id: dnsdist-actions-factory.cc LuaFFIPerThreadAction); tag pz says
-- which step this call is:
--   (unset)  If the rows were last confirmed current ≥ 1 s ago (or never): pz=gen. Otherwise
--            decide the pattern level (kept per wire name while the rows are unchanged); if
--            plain tables must be consulted: pz=plain or pz=head.
--   gen      pg = pattern_open["#gen"]: equal to the rows held → confirmed, go on; else pz=load.
--   load     pf = pattern_open["#pf"]: hold these rows, confirmed; go on.
--   plain    usual name with a pattern hit: qae/qal/qbl = allow_exact (exact), allow and block
--            (suffix) values of the qname → dnsdohDecide(…, false).
--   head     unusual name with a host prefix: tags h1..hN = its suffixes (wire keys) and
--            n<i>/a<i>/b<i> = block_nx/allow/block values for them, e1 = allow_exact for h1.
-- Staleness: a commit is seen by every query that starts ≥ 1 s after it (the per-thread
-- confirmation interval); between confirmations each thread answers from the rows it holds.
local ffi = require("ffi")
local C = ffi.C
pcall(ffi.cdef, "struct dnsdoh_ts { int64_t s; long ns; }; int clock_gettime(int clk, struct dnsdoh_ts *ts);")
local scan, plainLevel, UNUSUAL, unusualHead = M.scan, M.plainLevel, M.UNUSUAL, M.unusualHead
local FALLBACKS = "dnsdoh-filter-thread-fallbacks"   -- not lua-errors: the global stage decides
local NONE = DNSAction.None
local HMAX = 4                                        -- = the h<i> rules in filtering.lua
local HN, NN, AN, BN = {}, {}, {}, {}                  -- tag names h<i>, n<i>, a<i>, b<i>
for i = 1, HMAX do HN[i], NN[i], AN[i], BN[i] = "h" .. i, "n" .. i, "a" .. i, "b" .. i end
local CONFIRM = 1                                     -- seconds

-- Bytes of a usual name (UNUSUAL is [^a-z0-9%._%-] after lower()); '.' inside a label is
-- escaped by DNSName::toString (dnsname.cc appendEscapedLabel), so it is not usual here.
local USUAL = ffi.new("bool[256]")
for c = 0, 255 do USUAL[c] = string.char(c):match("^[A-Za-z0-9_%-]$") ~= nil end

local ts = ffi.new("struct dnsdoh_ts")
local function now() C.clock_gettime(1, ts); return tonumber(ts.s) + tonumber(ts.ns) * 1e-9 end   -- CLOCK_MONOTONIC

local function tag(dq, name)
  local v = C.dnsdist_ffi_dnsquestion_get_tag(dq, name)
  if v == nil then return nil end
  return ffi.string(v)
end
local function set(dq, name, value) C.dnsdist_ffi_dnsquestion_set_tag(dq, name, value) end
local function unset(dq, name) C.dnsdist_ffi_dnsquestion_unset_tag(dq, name) end
local function first(dq, names)                       -- first non-empty of names[1..] (lookupSuffix)
  for i = 1, #names do
    local v = tag(dq, names[i])
    if v and v ~= "" then return v end
  end
  return ""
end

local gen, confirmed = nil, -math.huge
local tails, open, star, all, maxrun = {}, {}, "", "", 0

-- The pattern part of a decision depends only on the qname and the rows held, so it is kept
-- per wire name (case as sent) until the rows change (load) or the cache fills. A record says
-- what the step does next: NONE (nothing), px, plain (pattern hit, plain tables next), head
-- (unusual name, its host prefix's plain tables next) or a verdict.
local CACHE_MAX = 16384
local cache, cached = {}, 0
local NONE_R, PX_R = { kind = "none" }, { kind = "px" }

-- Most names hit no `pattern` suffix and no `pattern_open` label run. A Bloom filter over those
-- keys (64 Kibit, two bits per key, 8 KiB) rejects them from bytes already in buf, without
-- building a substring for every candidate; a hit is confirmed in the real table. Label runs
-- hash forwards, suffixes backwards (so all suffixes of a name come from one backward pass).
local bit = require("bit")
local band, bor, bxor, rol, rshift, lshift = bit.band, bit.bor, bit.bxor, bit.rol, bit.rshift, bit.lshift
local H0 = bit.tobit(0x811c9dc5)
local bloom = ffi.new("uint8_t[8192]")
local function mixed(h)                               -- xorshift finaliser: bit ops only, exact
  h = bxor(h, lshift(h, 13)); h = bxor(h, rshift(h, 17)); return bxor(h, lshift(h, 5))
end
local function bloomSet(m, h)
  h = mixed(h)
  local a, b = band(h, 0xffff), band(rshift(h, 16), 0xffff)
  m[rshift(a, 3)] = bor(m[rshift(a, 3)], lshift(1, band(a, 7)))
  m[rshift(b, 3)] = bor(m[rshift(b, 3)], lshift(1, band(b, 7)))
end
local function bloomHas(h)
  h = mixed(h)
  local a, b = band(h, 0xffff), band(rshift(h, 16), 0xffff)
  return band(bloom[rshift(a, 3)], lshift(1, band(a, 7))) ~= 0 and band(bloom[rshift(b, 3)], lshift(1, band(b, 7))) ~= 0
end
local function fwd(s)                                 -- hash of s, bytes first to last
  local h = H0
  for i = 1, #s do h = bxor(rol(h, 5), s:byte(i)) end
  return h
end
local function bwd(s)                                 -- hash of s, bytes last to first
  local h = H0
  for i = #s, 1, -1 do h = bxor(rol(h, 5), s:byte(i)) end
  return h
end

local function load(blob)
  local g, body = blob:match("^pf3\t([^\30]+)(.*)$")
  if not g then error("#pf: bad header") end
  local t, o, s, a, m = {}, {}, nil, nil, 0
  for kind, k, v in body:gmatch("\30(.)([^\29]*)\29([^\30]*)") do
    if kind == "t" then t[k] = v
    elseif kind == "o" then
      o[k] = v
      local runs = select(2, k:gsub("%.", "")) + 1
      if runs > m then m = runs end                  -- compile resolve.rs max_run = "#maxrun"
    elseif kind == "s" then s = v
    elseif kind == "a" then a = v
    else error("#pf: bad record") end
  end
  if not s or not a then error("#pf: no scan rows") end
  local map = ffi.new("uint8_t[8192]")
  for k in pairs(t) do bloomSet(map, bwd(k)) end
  for k in pairs(o) do bloomSet(map, fwd(k)) end
  ffi.copy(bloom, map, 8192)
  tails, open, star, all, maxrun, gen = t, o, s, a, m, g
  cache, cached = {}, 0                              -- records depend on the rows
end

local qp, qn = ffi.new("const char *[1]"), ffi.new("size_t[1]")
local buf = ffi.new("uint8_t[256]")
local starts, ends = {}, {}
local sub, find, char, format = string.sub, string.find, string.char, string.format

-- dnsdohName(qname) = qname:toStringNoDot():lower() for an unusual name (dnsname.cc toString,
-- appendEscapedLabel: '.' → "\.", '\' → "\\", 0x21-0x7e as is, else "\DDD"), written into ebuf.
local ebuf = ffi.new("uint8_t[1024]")                -- ≤ 255 wire bytes × 4
local function escapedName(p)
  local o, pos = 0, 0
  while p[pos] ~= 0 do
    local l = p[pos]
    if pos > 0 then ebuf[o] = 46; o = o + 1 end
    for i = pos + 1, pos + l do
      local c = p[i]
      if c == 46 or c == 92 then ebuf[o] = 92; ebuf[o + 1] = c; o = o + 2
      elseif c > 32 and c < 127 then
        if c >= 65 and c <= 90 then c = c + 32 end  -- lower()
        ebuf[o] = c; o = o + 1
      else
        ebuf[o] = 92; ebuf[o + 1] = 48 + math.floor(c / 100); ebuf[o + 2] = 48 + math.floor(c / 10) % 10
        ebuf[o + 3] = 48 + c % 10; o = o + 4
      end
    end
    pos = pos + l + 1
  end
  return ffi.string(ebuf, o)
end

-- Tags pv (allow/block/nx) and list, as dnsdohPatternStage.
local function verdict(dq, v, src)
  set(dq, "pv", v)
  set(dq, "list", src)
end


local hsuf = {}
local function usual(name, k)
  local h = H0                                       -- hsuf[i] = bwd(sub(name, starts[i]))
  for i = k, 1, -1 do
    for x = ends[i], starts[i], -1 do h = bxor(rol(h, 5), buf[x]) end
    hsuf[i] = h
    h = bxor(rol(h, 5), 46)                          -- the '.' before label i
  end
  local best, src = 0, nil
  for i = 1, k do                                    -- T.pattern:lookupSuffix: longest key first
    if bloomHas(hsuf[i]) then
      local v = tails[sub(name, starts[i])]
      if v then best, src = scan(v, name, 0, nil); break end
    end
  end
  best, src = scan(star, name, best, src)
  for i = 1, k do
    local last = i + maxrun - 1
    if last > k then last = k end
    h = H0                                           -- fwd(sub(name, starts[i], ends[j]))
    for j = i, last do
      if j > i then h = bxor(rol(h, 5), 46) end
      for x = starts[j], ends[j] do h = bxor(rol(h, 5), buf[x]) end
      if bloomHas(h) then
        local v = open[sub(name, starts[i], ends[j])]
        if v then best, src = scan(v, name, best, src) end
      end
    end
  end
  if best == 0 then return NONE_R end
  return { kind = "plain", best = tostring(best), src = src }
end

local function unusual(name)
  local best, src = scan(all, name, 0, nil)
  local head, exact = unusualHead(name)
  if head then
    local labels = {}
    for l in head:gmatch("[^%.]+") do labels[#labels + 1] = l end
    if #labels > HMAX then return PX_R end
    local keys, key = {}, "\0"                      -- wire keys of the suffixes
    for i = #labels, 1, -1 do
      key = char(#labels[i]) .. labels[i] .. key
      keys[i] = key
    end
    return { kind = "head", best = tostring(best), src = src or "", exact = exact and "1" or "", keys = keys }
  end
  if best == 0 then return NONE_R end
  return { kind = "verdict", v = (best % 2 == 0) and "allow" or "block", src = src }
end

local function compute(p, len)
  local k, pos, odd = 0, 0, false
  while true do
    if pos >= len then error("qname: no terminating label") end
    local l = p[pos]
    if l == 0 then break end
    if l > 63 or pos + l >= len then error("qname: bad label") end
    buf[pos] = 46                                    -- '.' (buf[0] is dropped below)
    for i = pos + 1, pos + l do
      local c = p[i]
      if not USUAL[c] then odd = true end
      if c >= 65 and c <= 90 then c = c + 32 end    -- lower()
      buf[i] = c
    end
    k = k + 1
    starts[k], ends[k] = pos + 1, pos + l            -- 1-based positions in name
    pos = pos + l + 1
  end
  if k == 0 then return PX_R end                     -- root: the global stage decides
  if odd then return unusual(escapedName(p)) end
  return usual(ffi.string(buf + 1, pos - 1), k)      -- name == dnsdohName(qname)
end

local function patternStep(dq)
  C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, qp, qn)
  local len = tonumber(qn[0])
  local w = ffi.string(qp[0], len)
  local r = cache[w]
  if not r then
    r = compute(ffi.cast("const uint8_t *", qp[0]), len)
    if cached >= CACHE_MAX then cache, cached = {}, 0 end
    cache[w], cached = r, cached + 1
  end
  local kind = r.kind
  if kind == "none" then return
  elseif kind == "plain" then set(dq, "pb", r.best); set(dq, "pl", r.src); set(dq, "pz", "plain")
  elseif kind == "px" then set(dq, "px", "1")
  elseif kind == "head" then
    local keys = r.keys
    for i = 1, #keys do C.dnsdist_ffi_dnsquestion_set_tag_raw(dq, HN[i], keys[i], #keys[i]) end
    set(dq, "pb", r.best); set(dq, "pl", r.src); set(dq, "pe", r.exact); set(dq, "pz", "head")
  else verdict(dq, r.v, r.src) end
end

local function step(dq)
  local z = tag(dq, "pz")
  if z == nil then
    if now() - confirmed >= CONFIRM then set(dq, "pz", "gen"); return end
    patternStep(dq)
  elseif z == "gen" then
    unset(dq, "pz")
    if tag(dq, "pg") ~= gen then set(dq, "pz", "load"); return end
    confirmed = now()
    patternStep(dq)
  elseif z == "load" then
    unset(dq, "pz")
    load(tag(dq, "pf") or "")
    unset(dq, "pf")                                  -- large: not carried through the query
    confirmed = now()
    patternStep(dq)
  elseif z == "plain" then
    unset(dq, "pz")
    local best, src = tonumber(tag(dq, "pb")), tag(dq, "pl")
    local v = tag(dq, "qae") or ""
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = tag(dq, "qal") or ""
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = tag(dq, "qbl") or ""
    if v ~= "" and plainLevel(v, false) > best then best, src = plainLevel(v, false), v end
    verdict(dq, (best % 2 == 0) and "allow" or "block", src)
  elseif z == "head" then
    unset(dq, "pz")
    local best, src = tonumber(tag(dq, "pb")), tag(dq, "pl")
    local nx = first(dq, NN)                  -- block_nx precedes every allow
    if nx ~= "" then return verdict(dq, "nx", nx) end
    local v = tag(dq, "pe") == "1" and (tag(dq, "e1") or "") or ""
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = first(dq, AN)
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = first(dq, BN)
    if v ~= "" and plainLevel(v, false) > best then best, src = plainLevel(v, false), v end
    if best > 0 then verdict(dq, (best % 2 == 0) and "allow" or "block", src) end
  end
end

-- pv and list are set last in each step, so an error never leaves them behind.
local function failed(dq)
  C.dnsdist_ffi_metric_inc(FALLBACKS, #FALLBACKS)   -- counted; the global stage decides instead
  unset(dq, "pz"); unset(dq, "pf")
  set(dq, "px", "1")
end

-- An error escaping this function would make dnsdist answer SERVFAIL
-- (dnsdist-actions-factory.cc LuaFFIPerThreadAction::operator()), so nothing escapes.
-- dq arrives as a plain pointer, not cdata: passed as is to every FFI call, each call aborts
-- the JIT trace ("NYI: unsupported C type conversion", jit.v) and runs interpreted. One cast here.
local DQ = ffi.typeof("dnsdist_ffi_dnsquestion_t *")
return function(dq)
  dq = ffi.cast(DQ, dq)
  if not pcall(step, dq) then pcall(failed, dq) end
  return NONE
end
