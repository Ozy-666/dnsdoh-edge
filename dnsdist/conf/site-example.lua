-- Example site file. Copy, fill in your own addresses and paths, and point DNSDOH_SITE at it.
return {
  name             = "example",
  do53             = { "192.0.2.1:53" },
  dot              = "192.0.2.1:853",
  doq              = "192.0.2.1:853",
  doh              = "127.0.0.1:8053",      -- plain HTTP/2 behind a TLS-terminating proxy (grpc_pass)
  console          = "127.0.0.1:5199",
  console_key_file = "/etc/dnsdist/console.key",
  cert             = "/etc/dnsdist/tls/fullchain.pem",
  key              = "/etc/dnsdist/tls/privkey.pem",
  backend          = "127.0.0.1:5353",      -- Unbound
  filter_db        = "/var/lib/dnsdoh.art/filter.mdb",
  service_ip       = "192.0.2.1",
  acl              = { "0.0.0.0/0", "::/0" },
}
