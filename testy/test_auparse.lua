--test_auparse.lua
--[[
	Use the straight up 'C' interface to simply open
	a cursor, move to the next record, and close the cursor
--]]
package.path = ";../?.lua;"..package.path

local ffi = require("ffi")
local aup = require("auparse_ffi")

local cursor = aup.auparse_init(aup.AUSOURCE_LOGS, nil);

assert(cursor ~= nil, "auparse_init() failure")

-- move to the next event
local res = aup.auparse_next_event(cursor);
print("next_event: ", res)

aup.auparse_destroy(cursor)