-- Pattern stage and the shared level decision.
-- Value formats and scan(): match.lua (shared with the per-thread stage, patterns_thread.lua).
local M = dofile(CONF .. "/modules/match.lua")
local scan, plainLevel = M.scan, M.plainLevel
dnsdohMatch = M   -- exposed for tests

-- Characters outside [a-z0-9._-] ("unusual" names). The C++ tables are
-- skipped for these (filtering.lua) and dnsdohDecide decides them in full, as urlfilter does:
--  * `||d^` (tables block, allow, block_nx) is matched against "http://"+host (network.go:566-570)
--    as ^(http|https|ws|wss)://([a-z0-9-_.]+\.)?d([^ a-zA-Z0-9.%_-]|$) (regexp.go:40,48,
--    case-insensitive, network.go:544-545). With c = the first unusual char at i and
--    h = name:sub(1, i-1), all of [a-z0-9._-]: d must be h or a label suffix of h, and c must be
--    a separator (every unusual char except space and '%').
--  * `@@|d^|` (table allow_exact) is ^d([^ a-zA-Z0-9.%_-]|$)$ against the hostname
--    (regexp.go replacePrefix/replaceSuffix; shouldMatchHostname): d == h and c is the last char.
-- Known gap: `||d^|` is stored as a suffix like `||d^` (compile rule.rs Shape::Suffix) but is
-- end-anchored in urlfilter, so it matches an unusual name only when c is the last char.
local UNUSUAL = M.UNUSUAL

-- For an unusual name: the DNSName of h that `||d^` rules can match, and whether `@@|d^|` can
-- match too (c is the last char). nil when no plain rule can match.
local function unusualHead(name)
  local h, exact = M.unusualHead(name)
  if not h then return nil end
  return newDNSName(h), exact
end

local function patternLevel(dn, name)
  if name:find(UNUSUAL) then                           -- unusual names: every pattern
    return scan(T.pattern_open:lookup("**"), name, 0, nil)
  end
  local best, src = scan(T.pattern:lookupSuffix(dn), name, 0, nil)
  best, src = scan(T.pattern_open:lookup("*"), name, best, src)
  local labels = {}
  for l in name:gmatch("[^%.]+") do labels[#labels + 1] = l end
  local maxRun = tonumber(T.pattern_open:lookup("#maxrun")) or 0
  for i = 1, #labels do
    local key = labels[i]
    for j = i, math.min(#labels, i + maxRun - 1) do
      if j > i then key = key .. "." .. labels[j] end
      best, src = scan(T.pattern_open:lookup(key), name, best, src)
    end
  end
  return best, src
end

function dnsdohName(dn)
  return dn:toStringNoDot():lower()
end

-- Basic-rule decision (not rewrites). full=false: for a usual name, return early when no
-- pattern matched (the C++ tables then decide); full=true: always consult plain tables.
-- Unusual names are always decided here (see UNUSUAL); with full=false their block_nx hit
-- returns "nx" first, as block_nx precedes every allow (the response side ignores block_nx).
function dnsdohDecide(dn, name, full)
  local best, src = patternLevel(dn, name)
  local matched = best > 0
  local key, exact = dn, true
  if name:find(UNUSUAL) then
    key, exact = unusualHead(name)
    if key and not full then
      local v = T.block_nx:lookupSuffix(key)
      if v ~= "" then return "nx", v, matched end
    end
  elseif not matched and not full then
    return nil, nil, false
  end
  if key then
    local v = exact and T.allow_exact:lookup(key, true) or ""
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = T.allow:lookupSuffix(key)
    if v ~= "" and plainLevel(v, true) > best then best, src = plainLevel(v, true), v end
    v = T.block:lookupSuffix(key)
    if v ~= "" and plainLevel(v, false) > best then best, src = plainLevel(v, false), v end
  end
  if best == 0 then return nil, nil, matched, 0 end
  return (best % 2 == 0) and "allow" or "block", src, matched, best
end

-- Client-scoped rules ($client). Table client values: lines
-- "<level|nx>\t<value>\t<permit CIDRs, comma-sep>\t<deny CIDRs>"; each key carries its
-- ancestors' entries. An entry applies when the deny set does not contain the address and the
-- permit set is empty or contains it (urlfilter rules/network.go:703 matchClient).
local ccache, ccacheN = {}, 0
local function nmg(csv)
  if csv == "" then return nil end
  local g = newNMG()
  for m in csv:gmatch("[^,]+") do g:addMask(m) end
  return g
end
local function clientEntries(v)
  local e = ccache[v]
  if e then return e end
  e = {}
  for line in v:gmatch("[^\n]+") do
    local lvl, val, permit, deny = line:match("^(%w+)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
    e[#e + 1] = { nx = lvl == "nx", level = tonumber(lvl) or 0, value = val, permit = nmg(permit), deny = nmg(deny) }
  end
  if ccacheN >= 1024 then ccache, ccacheN = {}, 0 end   -- content-addressed, as for patterns
  ccache[v], ccacheN = e, ccacheN + 1
  return e
end

-- The key suffix lookups use for plain `||d^` rules: the name itself, or for an unusual name the
-- host prefix (unusualHead); nil when no plain rule can match.
local function plainKey(dn, name)
  if name:find(UNUSUAL) then return (unusualHead(name)) end
  return dn
end

-- Global $dnsrewrite=NXDOMAIN value for a name ("" when none), unusual names by host prefix.
function dnsdohGlobalNx(dn, name)
  local key = plainKey(dn, name)
  return key and T.block_nx:lookupSuffix(key) or ""
end

-- Decision for a name that has client entries matching addr (a ComboAddress); nil when none
-- applies, so the caller falls back to the global decision. $dnsrewrite rules (client or
-- global) precede every basic rule (AGH filtering.go:852-855):
--  full=false (question): a matching nx entry, or a global block_nx hit → "nx". Usual names never
--    reach here with a global block_nx hit (the C++ block_nx rule runs first); unusual ones may.
--  full=true (response): the same hit → "pass": AGH's result is then RewrittenRule, which is
--    never IsFiltered (filtering.go:900), so a block rule on the same name does not apply.
-- Otherwise the maximum level over the applying client entries and dnsdohDecide(…, full=true).
function dnsdohClientDecide(dn, name, addr, full)
  local key = plainKey(dn, name)
  if not key then return nil end
  local v = T.client:lookupSuffix(key)
  if v == "" then return nil end
  local best, src, nxsrc, any = 0, nil, nil, false
  for _, e in ipairs(clientEntries(v)) do
    if not (e.deny and e.deny:match(addr)) and (not e.permit or e.permit:match(addr)) then
      any = true
      if e.nx then nxsrc = nxsrc or e.value
      elseif e.level > best then best, src = e.level, e.value end
    end
  end
  if not any then return nil end
  if not nxsrc then
    local g = T.block_nx:lookupSuffix(key)
    if g ~= "" then nxsrc = g end
  end
  if nxsrc then return full and "pass" or "nx", nxsrc end
  local _, gsrc, _, gbest = dnsdohDecide(dn, name, true)
  if gbest > best then best, src = gbest, gsrc end
  return (best % 2 == 0) and "allow" or "block", src
end

-- Tags pv (allow/block/nx) and list when this stage decides: a pattern matched, or the name is
-- unusual (the C++ tables are skipped for it; filtering.lua forwards it when pv is unset).
function dnsdohPatternStage(dq)
  local ok = pcall(function()
    local name = dnsdohName(dq.qname)
    local verdict, src, matched = dnsdohDecide(dq.qname, name, false)
    if verdict and (matched or name:find(UNUSUAL)) then
      dq:setTag("pv", verdict)
      dq:setTag("list", src)
    end
  end)
  if not ok then incMetric("dnsdoh-filter-lua-errors") end
  return DNSAction.None, ""
end
