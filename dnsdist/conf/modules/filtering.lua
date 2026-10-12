-- Filtering: the question-side rule stages after the legacy rewrites (rewrite.lua). Tables are
-- opened in tables.lua.
-- KeyValueStoreLookupAction always creates the tag, even on a miss, so decisions use
-- KeyValueStoreLookupRule and never TagRule on "list" (tested trap, Phase 2).
local SFX, QN = KeyValueLookupKeySuffix(), KeyValueLookupKeyQName()
-- Names with characters outside [a-z0-9._-] skip the C++ tables: urlfilter matches them
-- differently (separator after the domain), so the Lua stage decides them in full
-- (patterns.lua UNUSUAL). POSIX ERE, REG_ICASE, over qname:toStringNoDot()
-- (dnsdist-rules-factory.hh:515, misc.cc:832).
local unusual = RegexRule("[^-a-z0-9._]")
-- A question-side allow (AGH NotFilteredAllowList) skips response filtering (process.go:450-452):
-- tag qa=1 before the terminal AllowAction; respfilter.lua returns early on it.
-- Every rule-based allow goes through here (the client-rule allow too); the unusual-name
-- no-rule forward below does not (AGH NotFilteredNotFound is response-filtered).
local function allowRule(rule)
  addAction(rule, SetTagAction("qa", "1"))
  addAction(rule, AllowAction())
end

-- $dnsrewrite=NXDOMAIN rules precede every allow (AGH filtering.go:852-855). AGH: NXDOMAIN, RA, no SOA.
local nx = AndRule({ NotRule(unusual), KeyValueStoreLookupRule(T.block_nx, SFX) })
addAction(nx, KeyValueStoreLookupAction(T.block_nx, SFX, "list"))
addAction(nx, RCodeAction(DNSRCode.NXDOMAIN, { ra = true }))

-- Client stage ($client rules): only for names with a client-rule key (C++ suffix lookup)
-- or unusual names (keyed by their host prefix, patterns.lua). Address = dq.remoteaddr: for DoH
-- with trustForwardedForHeader it is the last X-Forwarded-For address (dnsdist source at the
-- dnsdist/pins.env version: dnsdist-nghttp2-in.cc:918-925 → d_proxiedRemote → dnsdist-tcp.cc:817
-- ids.origRemote → dnsdist-lua-bindings-dnsquestion.cc:97 "remoteaddr"). Tags cv =
-- nx/allow/block and list.
local function clientStage(dq)
  local v, src = dnsdohClientDecide(dq.qname, dnsdohName(dq.qname), dq.remoteaddr, false)
  if v then
    dq:setTag("cv", v)
    dq:setTag("list", src)
  end
end
addAction(OrRule({ unusual, KeyValueStoreLookupRule(T.client, SFX) }), LuaAction(function(dq)
  if not pcall(clientStage, dq) then incMetric("dnsdoh-filter-lua-errors") end
  return DNSAction.None, ""
end))
addAction(TagRule("cv", "nx"), RCodeAction(DNSRCode.NXDOMAIN, { ra = true }))
allowRule(TagRule("cv", "allow"))
local cvBlock = TagRule("cv", "block")
addAction(AndRule({ cvBlock, QTypeRule(DNSQType.A) }), SpoofAction({ "0.0.0.0" }, { ttl = 300, ra = true }))
addAction(cvBlock, NODATA)

-- Pattern stage: decides the query itself when any pattern matches, per thread
-- (patterns_thread.lua: no global Lua lock; pattern rows held in memory, reloaded when
-- pattern_open["#gen"] changes, checked at most once a second per thread). LMDB is read by the
-- C++ actions below, into tags, only when that step needs it; a fixed or computed key comes
-- from a tag via KeyValueLookupKeyTag (dnsdist-kvs.hh:125-142). Tag px (root name, long host
-- prefix, any error, a stage that failed to load) hands the query to dnsdohPatternStage in the
-- global state (patterns.lua); errors and load failures count in dnsdoh-filter-thread-fallbacks.
if SITE.patterns ~= false then
  local function slurp(f)
    local h = assert(io.open(CONF .. "/modules/" .. f, "r"))
    local s = h:read("*a"); h:close(); return s
  end
  -- dnsdist marks a per-thread state initialised BEFORE running its code, and a state whose
  -- code failed returns DNSAction.None on every later query (dnsdist-actions-factory.cc:678-690:
  -- `state.d_initialized = true; state.d_func = …executeCode…`, `if (!state.d_func) return None`):
  -- a silent bypass. So the code dnsdist runs is this fixed wrapper; the stage is compiled and
  -- run inside it under pcall (a syntax error included). If that fails, every query on that
  -- thread is counted in dnsdoh-filter-thread-fallbacks and handed to the global stage (px).
  local body = "local M = (function()\n" .. slurp("match.lua") .. "\nend)()\n" .. slurp("patterns_thread.lua")
  local stage = LuaFFIPerThreadAction(string.format([[
local ok, f = pcall(function()
  local chunk, err = loadstring(%q, "=patterns_thread")
  if not chunk then error(err) end
  local fn = chunk()
  if type(fn) ~= "function" then error("stage chunk returned " .. type(fn)) end
  return fn
end)
if ok then return f end
pcall(errlog, "dnsdoh per-thread pattern stage failed to load, using the global stage: " .. tostring(f))
local ffi = require("ffi")
local C = ffi.C
local FB = "dnsdoh-filter-thread-fallbacks"
local DQ = ffi.typeof("dnsdist_ffi_dnsquestion_t *")
local NONE = DNSAction.None
local function fallback(dq)
  dq = ffi.cast(DQ, dq)
  C.dnsdist_ffi_metric_inc(FB, #FB)
  C.dnsdist_ffi_dnsquestion_set_tag(dq, "px", "1")
end
return function(dq) pcall(fallback, dq); return NONE end
]], body))
  local function pz(v) return TagRule("pz", v) end
  local function byTag(t, key, dest) return KeyValueStoreLookupAction(t, KeyValueLookupKeyTag(key), dest) end
  addAction(AllRule(), stage)
  addAction(pz("gen"), SetTagAction("pk", "#gen"))
  addAction(pz("gen"), byTag(T.pattern_open, "pk", "pg"))
  addAction(pz("gen"), stage)
  addAction(pz("load"), SetTagAction("pk", "#pf"))
  addAction(pz("load"), byTag(T.pattern_open, "pk", "pf"))
  addAction(pz("load"), stage)
  addAction(pz("plain"), KeyValueStoreLookupAction(T.allow_exact, QN, "qae"))
  addAction(pz("plain"), KeyValueStoreLookupAction(T.allow, SFX, "qal"))
  addAction(pz("plain"), KeyValueStoreLookupAction(T.block, SFX, "qbl"))
  addAction(pz("plain"), stage)
  addAction(TagRule("h1"), byTag(T.allow_exact, "h1", "e1"))
  for i = 1, 4 do                                   -- = HMAX in patterns_thread.lua
    local h = TagRule("h" .. i)
    addAction(h, byTag(T.block_nx, "h" .. i, "n" .. i))
    addAction(h, byTag(T.allow, "h" .. i, "a" .. i))
    addAction(h, byTag(T.block, "h" .. i, "b" .. i))
  end
  addAction(pz("head"), stage)
  addAction(TagRule("px", "1"), LuaAction(dnsdohPatternStage))
end
local pvNx = TagRule("pv", "nx")                  -- unusual names only (patterns.lua)
addAction(pvNx, RCodeAction(DNSRCode.NXDOMAIN, { ra = true }))
allowRule(TagRule("pv", "allow"))
local pvBlock = TagRule("pv", "block")
addAction(AndRule({ pvBlock, QTypeRule(DNSQType.A) }), SpoofAction({ "0.0.0.0" }, { ttl = 300, ra = true }))
addAction(pvBlock, NODATA)
addAction(unusual, AllowAction())   -- the Lua stage found no rule for an unusual name: AGH passes it

-- Plain tables, Phase 2 order: allow exact, allow suffix, block suffix (pruned level-correct).
allowRule(KeyValueStoreLookupRule(T.allow_exact, QN))
allowRule(KeyValueStoreLookupRule(T.allow, SFX))
local hit = KeyValueStoreLookupRule(T.block, SFX)
addAction(hit, KeyValueStoreLookupAction(T.block, SFX, "list"))
addAction(AndRule({ hit, QTypeRule(DNSQType.A) }), SpoofAction({ "0.0.0.0" }, { ttl = 300, ra = true }))
addAction(hit, NODATA)
