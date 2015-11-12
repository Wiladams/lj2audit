--test_auparse.lua

package.path = package.path..";../src/?.lua"

local ffi = require("ffi")
local aup = require("auparse_ffi")

local cursor = aup.auparse_init(aup.AUSOURCE_LOGS, nil);

assert(cursor ~= nil, "auparse_init() failure")

ffi.gc(cursor, aup.auparse_destroy)

-- move to the next event
local res = aup.auparse_next_event(cursor);
print("next_event: ", res)

