-- dnsdoh.art dnsdist entry point. DNSDOH_SITE picks the site file (addresses/paths);
-- modules hold behaviour and load in this fixed order, which is the rule order.
CONF = os.getenv("DNSDOH_CONF_DIR") or "/etc/dnsdoh.art/dnsdist"
local site = os.getenv("DNSDOH_SITE") or error("DNSDOH_SITE is not set (a site name in CONF, or an absolute path)")
SITE = dofile(site:sub(1, 1) == "/" and site or (CONF .. "/" .. site .. ".lua"))

-- Shared NODATA answer: SOA in authority (cacheable, as AGH), TTL 300, RA set.
NODATA = NegativeAndSOAAction(false, "blocked.dnsdoh.art.", 300,
  "fake-for-negative-caching.dnsdoh.art.", "hostmaster.dnsdoh.art.",
  100500, 1800, 900, 604800, 86400, { soaInAuthoritySection = true, ra = true })

local function loadExtra(list) for _, m in ipairs(list or {}) do dofile(CONF .. "/modules/" .. m) end end
dofile(CONF .. "/modules/listeners.lua")
dofile(CONF .. "/modules/tables.lua")     -- opens filter tables; refuses a DB without them
dofile(CONF .. "/modules/patterns.lua")   -- functions only, no rules
dofile(CONF .. "/modules/respfilter.lua") -- response filter: before the AA clear
dofile(CONF .. "/modules/aaclear.lua")
loadExtra(SITE.pre_policy_modules)        -- site-specific modules that must precede terminal actions
dofile(CONF .. "/modules/policy.lua")
dofile(CONF .. "/modules/rewrite.lua")
dofile(CONF .. "/modules/filtering.lua")
loadExtra(SITE.final_modules)             -- site-specific modules that run last
