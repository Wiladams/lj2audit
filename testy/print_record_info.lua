--print_record_info.lua
--[[
	Print records in a reasonable report looking format
--]]

package.path = package.path..";../../?.lua"

local AUCursor = require("lj2audit.AUCursor")
local fun = require("lj2audit.fun")


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
