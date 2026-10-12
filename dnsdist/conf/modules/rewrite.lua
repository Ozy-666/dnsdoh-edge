-- Legacy rewrites (compile/src/rewrites.rs): exact name, before every rule; data from
-- table `rewrite` ("A <ip>"). dq:spoof answers with TTL 60 (dnsdist-dnsparser.hh:79), so a
-- self-answered response action sets TTL 300 and RA, as AGH answers.
local function rewrite(dq)
  local ip = T.rewrite:lookup(dq.qname, true):match("^A (%S+)$")
  if ip and dq.qtype == DNSQType.A then
    dq:setTag("rw", "1")
    dq:spoof({ newCA(ip) })
    return DNSAction.HeaderModify, ""
  end
  dq:setTag("rw", "nodata")
  return DNSAction.None, ""
end
addAction(KeyValueStoreLookupRule(T.rewrite, KeyValueLookupKeyQName()), LuaAction(function(dq)
  local ok, action, arg = pcall(rewrite, dq)
  if ok then return action, arg end
  incMetric("dnsdoh-filter-lua-errors")
  return DNSAction.None, ""
end))
addAction(TagRule("rw", "nodata"), NODATA)
-- A Lua error in a response action turns the answer into SERVFAIL, so the
-- edit runs under pcall: on error the rewrite answer goes out unedited and is counted.
local function ttlRA(dr)
  dr:editTTLs(function(section, qclass, qtype, ttl) return 300 end)
  dr.dh:setRA(true)
end
addSelfAnsweredResponseAction(TagRule("rw", "1"), LuaResponseAction(function(dr)
  if not pcall(ttlRA, dr) then incMetric("dnsdoh-filter-lua-errors") end
  return DNSResponseAction.None, ""
end))
