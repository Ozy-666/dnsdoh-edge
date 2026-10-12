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
newServer({ address = SITE.backend, name = "unbound" })                       -- pool "": DoT/DoH/DoQ
-- DNS cookies (unbound/README.md): port-53 traffic (UDP and TCP) goes to unbound's PROXYv2
-- listener, so unbound mints DNS cookies against the real client address. No fallback to the plain
-- backend: it would silently mint 127.0.0.1-bound cookies. Must stay the first rule (answers dnsdist
-- generates never reach a backend, so pool choice only affects forwarded queries). No packet cache.
newServer({ address = (assert(SITE.backend_pp, "site has no backend_pp")), name = "unbound-pp",
            pool = "do53", useProxyProtocol = true })
addAction(OrRule({ IncomingProtocolRule("DoUDP"), IncomingProtocolRule("DoTCP") }), PoolAction("do53", false))

local kf = assert(io.open(SITE.console_key_file, "r"), "console key missing: " .. SITE.console_key_file)
setKey(kf:read("*l")); kf:close()
controlSocket(SITE.console)
setConsoleACL({ "127.0.0.1/32" })
