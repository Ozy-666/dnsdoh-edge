-- Filter DB tables (written by compile/src/emit.rs). LMDB readers see the latest committed transaction.
local f = io.open(SITE.filter_db, "r")
assert(f, "filter DB missing: " .. SITE.filter_db .. " (refusing to serve unfiltered)")
f:close()
T = {}
for _, name in ipairs({ "block", "allow", "allow_exact", "block_nx", "pattern", "pattern_open", "ip_block", "rewrite", "client" }) do
  local ok, kvs = pcall(newLMDBKVStore, SITE.filter_db, name)
  assert(ok and kvs, "filter DB has no table '" .. name .. "': run dnsdoh.art-compile (refusing to serve half-filtered)")
  T[name] = kvs
end
-- The compiler always writes the canary and #maxrun; without them this is not its DB.
assert(T.block:lookup(newDNSName("canary.dnsdoh-filter.invalid."), true) == "CANARY",
  "filter DB has no canary in table block: " .. SITE.filter_db .. " (refusing to serve unfiltered)")
assert(T.pattern_open:lookup("#maxrun") ~= "",
  "filter DB has no pattern tables: run dnsdoh.art-compile (refusing to serve half-filtered)")
assert(T.pattern_open:lookup("#gen") ~= "" and T.pattern_open:lookup("#pf"):sub(1, 4) == "pf3\t",
  "filter DB has no per-thread pattern rows (#gen/#pf): run dnsdoh.art-compile (refusing to serve half-filtered)")
declareMetric("dnsdoh-filter-lua-errors", "counter", "Lua errors in dnsdoh filtering; those answers passed unfiltered")
declareMetric("dnsdoh-filter-thread-fallbacks", "counter",
  "Queries the per-thread pattern stage handed to the global stage after an error or a failed load; decided there, filtered")
