--print_record_info.lua
--[[
	Print records in a reasonable report looking format
--]]

package.path = package.path..";../src/?.lua"

local AUCursor = require("AUCursor")
local fun = require("fun")


local function printRecords(cursor)
	for _, event in cursor:events() do
		print("============================")
		for idx, record in cursor:records() do
			fun.each(print, record)
			print("--------------------------")
			fun.each(print, record.fields)
		end
	end
end

printRecords(AUCursor());
