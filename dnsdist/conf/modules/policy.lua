-- Query policy: the rules that run before filtering.
addAction(QTypeRule(DNSQType.ANY), RCodeAction(DNSRCode.NOTIMP))      -- AGH refuse_any
addAction(QTypeRule(DNSQType.AAAA), NODATA)                           -- AGH aaaa_disabled; no IPv6

-- DDR (RFC 9462), ranked 1 DoH / 2 DoQ / 3 DoT, identical to AGH (tested).
local H = { SITE.service_ip }
addAction(AndRule({ QTypeRule(DNSQType.SVCB), QNameRule("_dns.resolver.arpa.") }), SpoofSVCAction({
  newSVCRecordParameters(1, "dnsdoh.art.", { alpn = { "h3", "h2" }, port = 443, ipv4hint = H, key7 = "/dns-query{?dns}" }),
  newSVCRecordParameters(2, "dnsdoh.art.", { alpn = { "doq" }, port = 853, ipv4hint = H }),
  newSVCRecordParameters(3, "dnsdoh.art.", { alpn = { "dot" }, port = 853, ipv4hint = H }),
}, { ttl = 300, ra = true }))
addAction(QNameRule("_dns.resolver.arpa."), NODATA)
