-- Listeners, backend, console.
setACL((assert(SITE.acl, "site has no acl")))                       -- no silent default
setLocal(SITE.do53[1])
for i = 2, #SITE.do53 do addLocal(SITE.do53[i]) end
addTLSLocal(SITE.dot, SITE.cert, SITE.key, { provider = "openssl" })  -- ALPN "dot" is built in
addDOQLocal(SITE.doq, SITE.cert, SITE.key)
addDOHLocal(SITE.doh, nil, nil, "/dns-query",
  { trustForwardedForHeader = true, keepIncomingHeaders = true })     -- behind nginx only
setUDPSocketBufferSizes(4194304, 4194304)                             -- fork parity: 4 MiB
setUDPTimeout(1)                                                      -- AGH upstream_timeout: 1s
newServer({ address = SITE.backend, name = "unbound" })                       -- every transport

local kf = assert(io.open(SITE.console_key_file, "r"), "console key missing: " .. SITE.console_key_file)
setKey(kf:read("*l")); kf:close()
controlSocket(SITE.console)
setConsoleACL({ "127.0.0.1/32" })
