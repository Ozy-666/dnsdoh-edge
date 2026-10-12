-- Response filter: CNAME targets get the basic-rule decision (a block_nx hit
-- passes the record instead of blocking it; no legacy rewrites: AGH's response check,
-- dnsforward/filter.go:151, filtering.go:852-855, :900); A answers
-- are looked up in ip_block. A blocked answer is rebuilt with dr:setContent.
-- dnsdist overlay (dnsdist-dnsparser.cc:47-63 at the dnsdist/pins.env version): records of all
-- three sections, 0-based getRecord index, place 1/2/3 = answer/authority/additional,
-- contentOffset = 0-based offset of the RDATA in the packet.
local bit = require("bit")
local function u16(n) return string.char(bit.band(bit.rshift(n, 8), 255), bit.band(n, 255)) end
local function u32(n) return u16(math.floor(n / 65536)) .. u16(n % 65536) end
local function wire(name)
  local out = {}
  for l in name:gmatch("[^%.]+") do out[#out + 1] = string.char(#l) .. l end
  return table.concat(out) .. "\0"
end
-- Same SOA values as NODATA in dnsdist.lua.
local soaRdata = wire("fake-for-negative-caching.dnsdoh.art") .. wire("hostmaster.dnsdoh.art")
  .. u32(100500) .. u32(1800) .. u32(900) .. u32(604800) .. u32(86400)
local SOA = wire("blocked.dnsdoh.art") .. u16(6) .. u16(1) .. u32(300) .. u16(#soaRdata) .. soaRdata
local A0 = "\192\12" .. u16(1) .. u16(1) .. u32(300) .. u16(4) .. "\0\0\0\0"

local function blocked(pkt, ov, total)
  local qend = 12 + ov.qname:wirelength() + 4
  local opt = ""
  for i = 0, total - 1 do
    local r = ov:getRecord(i)
    -- OPT owner is the root (1 byte) + type, class, ttl, rdlength = 11 bytes before the RDATA.
    if r.type == 41 then opt = pkt:sub(r.contentOffset - 11 + 1, r.contentOffset + r.contentLength) end
  end
  local isA = ov.qtype == DNSQType.A
  local f1 = bit.band(pkt:byte(3), 0xFB)          -- clear AA
  local f2 = bit.band(pkt:byte(4), 0x90)          -- keep RA, CD; clear Z, AD, rcode
  return pkt:sub(1, 2) .. string.char(f1, f2) .. u16(1) .. u16(isA and 1 or 0) .. u16(isA and 0 or 1)
    .. u16(opt ~= "" and 1 or 0) .. pkt:sub(13, qend) .. (isA and A0 or SOA) .. opt
end

-- Per-record decision: the deciding value when this answer record blocks the response, else nil.
local function recordHit(dr, pkt, r)
  if r.place ~= 1 then return nil end
  if r.type == 5 then
    local target = parseCNAMERecord(pkt, r)
    local name = dnsdohName(target)
    -- Client rules first (AGH passes the client address to the response check,
    -- dnsforward/filter.go:128); "pass" when a $dnsrewrite rule matches (patterns.lua).
    local verdict, src = dnsdohClientDecide(target, name, dr.remoteaddr, true)
    if not verdict then
      -- A matching $dnsrewrite rule makes AGH's matchHost return RewrittenRule before any basic
      -- rule (filtering.go:852-855), which is never IsFiltered (filtering.go:900): pass.
      if dnsdohGlobalNx(target, name) ~= "" then return nil end
      verdict, src = dnsdohDecide(target, name, true)   -- full: never "nx"
    end
    if verdict == "block" then return src end
  elseif r.type == 1 then
    local v = T.ip_block:lookup(parseAddressRecord(pkt, r):getRaw())
    if v ~= "" then return v end
  end
  return nil
end

local function respFilter(dr)
  if dr:getTag("qa") == "1" then return end          -- question allowed (filtering.lua allowRule)
  local pkt = dr:getContent()
  local ov = newDNSPacketOverlay(pkt)
  if ov:getRecordsCountInSection(1) == 0 then return end
  local total = ov:getRecordsCountInSection(1) + ov:getRecordsCountInSection(2) + ov:getRecordsCountInSection(3)
  for i = 0, total - 1 do
    local hit = recordHit(dr, pkt, ov:getRecord(i))
    if hit then
      dr:setTag("list", hit)
      dr:setContent(blocked(pkt, ov, total))
      return
    end
  end
end

addResponseAction(AllRule(), LuaResponseAction(function(dr)
  if not pcall(respFilter, dr) then incMetric("dnsdoh-filter-lua-errors") end
  return DNSResponseAction.None, ""
end))
