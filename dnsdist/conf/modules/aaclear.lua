-- Clear AA on every answer, as the previous resolver did (fork parity).
-- A module of its own: it applies to every answer, whatever else a site loads.
addResponseAction(AllRule(), LuaResponseAction(function(dr)
  if not pcall(function() dr.dh:setAA(false) end) then incMetric("dnsdoh-filter-lua-errors") end
  return DNSResponseAction.None, ""
end))
