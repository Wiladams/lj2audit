--test_auparse.lua

package.path = ";../?.lua;"..package.path

local AUCursor = require("lj2audit.AUCursor")
local fun = require("lj2audit.fun")


local function printTable(cursor)

	io.write(string.format("return {\n"))

	for _, event in cursor:events() do
		--print("Event: ", event, cursor:numRecords())

		for _, record in cursor:records() do
			io.write(string.format("\t{\n"))
			io.write(string.format("\t\trecordFilename = %s,\n", cursor:recordFilename()))
			io.write(string.format("\t\trecordLineNumber = %d,\n", cursor:recordLineNumber()))
			io.write(string.format("\t\trecordType = %d,\n", cursor:recordType()))
			io.write(string.format("\t\trecordNumberOfFields = %d,\n", cursor:recordNumFields()))
--			io.write(string.format("\trecordText = [[%s]],\n", recordString))
		
			io.write(string.format("\t\tfields = {\n"))
			-- for each record, print the fields, if any
			for fieldname,fieldvalue in pairs(record.fields) do
				io.write(string.format("\t\t\t['%s'] = '%s',\n", fieldname, fieldvalue))
			end
			io.write(string.format("\t\t},\n"))

			-- finish out the record
			io.write(string.format("\t},\n"));

		end
	end

	io.write(string.format("}\n"))
end


printTable(AUCursor());
