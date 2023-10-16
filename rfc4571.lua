-- @brief rfc4571 Protocol dissector plugin
-- @author agdsdl
-- @date 2020.1.11

-- create a new dissector
local NAME = "rfc4571"
local PORT = 7777
local rfc4571 = Proto(NAME, "rfc4571")

-- create fields of rfc4571
local field_len = ProtoField.uint16 ("rfc4571.len", "len")
rfc4571.fields = { field_len }

-- dissect packet
function dissectFullRFC4571 (tvb, pinfo, tree)
	-- rfc4571 packet frame
    --  0                   1                   2                   3
    --  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    --  ---------------------------------------------------------------
    -- |             LENGTH            |  RTP or RTCP packet ...       |
    --  ---------------------------------------------------------------
    
    if tvb:len() < 6 then return 0 end

    local ver = tvb:range(2,1)
    ver = ver:bitfield(0,2)
    if ver ~= 2 then return 0 end

    local subtree = tree:add(rfc4571, tvb())
    local offset = 0
        
    subtree:add(field_len, tvb:range(offset,2):uint())
    offset = offset + 2
    
    Dissector.get("rtp"):call(tvb:range(offset):tvb(), pinfo, tree)

    -- append "rfc4571" to protocol name, eg. "rtp" -> "rtp(rfc4571)"
    pinfo.cols.protocol:append("(rfc4571)")

    return tvb:len()
end

function getRFC4571Len (tvb, pinfo, offset)
    local data_len = tvb:range(offset, 2):uint()
    -- Check pkt size, if too big, print error info
    if (data_len > 1500) then
        local err = string.format('pkt(index=%d) is too big (len=%d 0x%x) !!', pinfo.number, data_len, data_len)
        print(err)
    end
    return (data_len+2)
end

function rfc4571.dissector (tvb, pinfo, tree)
    return dissect_tcp_pdus(tvb, tree, 6, getRFC4571Len, dissectFullRFC4571, true)
end

-- register this dissector
DissectorTable.get("tcp.port"):add(PORT, rfc4571)
