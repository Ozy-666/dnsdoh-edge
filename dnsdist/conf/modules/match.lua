-- Pattern matching shared by the global Lua state (patterns.lua) and the per-thread pattern stage
-- (patterns_thread.lua, which has no dnsdist globals): plain string functions only, no KVS.
-- Pattern values: lines "<level>\t<value>\t<luapat>\31<luapat>..." joined by "\n" (rows: compile/src/emit.rs).
-- Plain values: "L<id>"/"U<line>", "!" appended when $important.
local find, sub, byte = string.find, string.sub, string.byte
local ffi, bit = require("ffi"), require("bit")
local band, bor, lshift, rshift = bit.band, bit.bor, bit.lshift, bit.rshift

-- What every match of Lua pattern p must satisfy, cheap to test with plain finds: each string in
-- runs occurs in the subject; head (if set) starts it; tail (if set) ends it. nil = nothing is
-- claimed (p is then always evaluated, so a malformed p still raises under pcall). A run is a
-- maximal sequence of single-character literal items without a quantifier. Follows Lua 5.1
-- lstrlib.c: an item is `.`, `%x`, `[set]` or a plain char, optionally followed by `*`, `+`,
-- `-` or `?`; `^` is an anchor only first, `$` only last; a set ends at the first `]` after its
-- first char (classEnd); `%x` with x not alphanumeric is the literal x. `%b`, `%f`,
-- back-references and captures claim nothing (never generated).
local function factsOf(p)
  local runs, head, tail, cur = {}, nil, nil, ""
  local i, n = 1, #p
  local atStart = sub(p, 1, 1) == "^"                -- cur starts at the subject's first char
  if atStart then i = 2 end
  local function flush()
    if cur ~= "" then
      runs[#runs + 1] = cur
      if atStart then head = cur end
    end
    cur, atStart = "", false
  end
  while i <= n do
    local c, lit, j = sub(p, i, i), nil, nil
    if c == "$" and i == n then
      if cur ~= "" then tail = cur end               -- cur ends at the subject's last char
      break
    elseif c == "(" or c == ")" then return nil
    elseif c == "%" then
      local x = sub(p, i + 1, i + 1)
      if x == "" or x == "b" or x == "f" or find(x, "^%d$") then return nil end
      if not find(x, "^%a$") then lit = x end       -- %. %- %%: the char; %a %w …: a class
      j = i + 2
    elseif c == "[" then
      j = i + 1
      if sub(p, j, j) == "^" then j = j + 1 end
      repeat
        if j > n then return nil end
        local d = sub(p, j, j)
        j = j + 1
        if d == "%" then j = j + 1 end
      until sub(p, j, j) == "]"
      j = j + 1
    elseif c == "." then j = i + 1
    else lit, j = c, i + 1 end
    local q = sub(p, j, j)
    if q == "*" or q == "-" or q == "?" then         -- the item may be absent
      flush(); i = j + 1
    elseif q == "+" then                             -- present once at least; more may follow
      if lit then cur = cur .. lit end
      flush(); i = j + 1
    else
      if lit then cur = cur .. lit else flush() end
      i = j
    end
  end
  flush()
  return { runs = runs, head = head, tail = tail }
end

-- May p match name, by its facts? (false only when it cannot.)
local function possible(f, name)
  if not f then return true end
  local h, t = f.head, f.tail
  if h and find(name, h, 1, true) ~= 1 then return false end
  if t and (#name < #t or not find(name, t, #name - #t + 1, true)) then return false end
  local runs = f.runs
  for r = 1, #runs do
    if not find(name, runs[r], 1, true) then return false end
  end
  return true
end

-- Long lists get an index: per pattern, one of its runs (≥ 3 chars; the one fewest patterns of
-- this list share, then the longest), keyed by its first three bytes and gated by a 64 Kibit
-- bitmap of those keys (one test per name position, in 8 KiB). A pattern with no such run makes
-- its entry always a candidate. Any run is required by every match, so the choice is sound.
local INDEX_MIN = 16
local function key3(b1, b2, b3) return b1 * 65536 + b2 * 256 + b3 end
local function bit3(b1, b2, b3) return band(b1 * 7919 + b2 * 263 + b3, 65535) end
local function index(e)
  local shared = {}
  for _, x in ipairs(e) do
    for _, f in ipairs(x.facts) do
      if f then
        local seen = {}
        for _, r in ipairs(f.runs) do
          if not seen[r] then seen[r] = true; shared[r] = (shared[r] or 0) + 1 end
        end
      end
    end
  end
  local idx, always, map = {}, {}, ffi.new("uint8_t[8192]")
  for k, x in ipairs(e) do
    for _, f in ipairs(x.facts) do
      local lit = ""
      if f then
        for _, r in ipairs(f.runs) do
          if #r >= 3 and (lit == "" or shared[r] < shared[lit] or (shared[r] == shared[lit] and #r > #lit)) then lit = r end
        end
      end
      if lit == "" then always[#always + 1] = k; break end
      local b1, b2, b3 = byte(lit, 1, 3)
      local key, h = key3(b1, b2, b3), bit3(b1, b2, b3)
      map[rshift(h, 3)] = bor(map[rshift(h, 3)], lshift(1, band(h, 7)))
      local l = idx[key]
      if not l then l = {}; idx[key] = l end
      l[#l + 1] = k; l[#l + 1] = lit
    end
  end
  e.idx, e.always, e.map, e.seen = idx, always, map, {}
end

local cache, cacheN = {}, 0
local function entries(v)
  local e = cache[v]
  if e then return e end
  e = {}
  local npats = 0
  for line in v:gmatch("[^\n]+") do
    local lvl, val, pats = line:match("^(%d)\t([^\t]*)\t(.*)$")
    local p, l = {}, {}
    for pat in pats:gmatch("[^\31]+") do p[#p + 1] = pat; l[#l + 1] = factsOf(pat) or false end
    e[#e + 1] = { level = tonumber(lvl), value = val, pats = p, facts = l }
    npats = npats + #p
  end
  if npats >= INDEX_MIN then index(e) end
  if cacheN >= 4096 then cache, cacheN = {}, 0 end   -- values are content-addressed: safe across commits
  cache[v], cacheN = e, cacheN + 1
  return e
end

-- Entry numbers (ascending, in ks[1..n]) that may match name, for an indexed list. ks and the
-- per-list seen marks are reused across calls (stamp), so a call allocates nothing.
local ks, stamp = {}, 0
local function candidates(e, name)
  stamp = stamp + 1
  local seen, n = e.seen, 0
  for _, k in ipairs(e.always) do
    if seen[k] ~= stamp then seen[k] = stamp; n = n + 1; ks[n] = k end
  end
  local idx, map, len = e.idx, e.map, #name
  local b1, b2 = byte(name, 1, 2)
  for i = 1, len - 2 do
    local b3 = byte(name, i + 2)
    local h = bit3(b1, b2, b3)
    if band(map[rshift(h, 3)], lshift(1, band(h, 7))) ~= 0 then
      local l = idx[key3(b1, b2, b3)]
      if l then
        for x = 1, #l, 2 do
          local k = l[x]
          if seen[k] ~= stamp and find(name, l[x + 1], i, true) == i then seen[k] = stamp; n = n + 1; ks[n] = k end
        end
      end
    end
    b1, b2 = b2, b3
  end
  for i = 2, n do                                   -- insertion sort: n is small
    local k, j = ks[i], i - 1
    while j >= 1 and ks[j] > k do ks[j + 1] = ks[j]; j = j - 1 end
    ks[j + 1] = k
  end
  return n
end

local function plainLevel(v, allow)
  local imp = v:sub(-1) == "!"
  if allow then return imp and 4 or 2 end
  return imp and 3 or 1
end

-- The first entry (in value order) with the highest level above best whose pattern matches.
-- Patterns whose facts rule the name out are skipped: the result is the same.
local function try(e, name, best, src)
  if e.level > best then
    local facts = e.facts
    for i, p in ipairs(e.pats) do
      if possible(facts[i], name) and find(name, p) then return e.level, e.value end
    end
  end
  return best, src
end

local function scan(v, name, best, src)
  if v == "" then return best, src end
  local es = entries(v)
  if es.idx then
    for i = 1, candidates(es, name) do best, src = try(es[ks[i]], name, best, src) end
  else
    for k = 1, #es do best, src = try(es[k], name, best, src) end
  end
  return best, src
end

-- Characters outside [a-z0-9._-]: "unusual" names (patterns.lua explains the matching).
local UNUSUAL = "[^a-z0-9%._%-]"

-- For an unusual name: the host prefix h whose `||d^` rules can match (patterns.lua), as a
-- string, and whether `@@|d^|` can match too; nil when no plain rule can match.
local function unusualHead(name)
  local i = find(name, UNUSUAL)
  local c = sub(name, i, i)
  if i == 1 or c == " " or c == "%" or sub(name, i - 1, i - 1) == "." then return nil end
  return sub(name, 1, i - 1), i == #name
end

return { factsOf = factsOf, possible = possible, scan = scan, plainLevel = plainLevel, UNUSUAL = UNUSUAL, unusualHead = unusualHead }
