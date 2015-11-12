--test_auparse.lua

package.path = package.path..";../src/?.lua"

local AUCursor = require("AUCursor")
local fun = require("fun")


local function printTable(cursor)

	io.write(string.format("return {\n"))

	for _, event in cursor:events() do
		--print("Event: ", event, cursor:numRecords())

		for _, recordString in cursor:recordStrings() do
			io.write(string.format("\t{\n"))
			io.write(string.format("\t\trecordFilename = %s,\n", cursor:recordFilename()))
			io.write(string.format("\t\trecordLineNumber = %d,\n", cursor:recordLineNumber()))
			io.write(string.format("\t\trecordType = %d,\n", cursor:recordType()))
			io.write(string.format("\t\trecordNumberOfFields = %d,\n", cursor:recordNumFields()))
--			io.write(string.format("\trecordText = [[%s]],\n", recordString))
		
			io.write(string.format("\t\tfields = {\n"))
			-- for each record, print the fields, if any
			for _, fieldname, fieldtype, fieldvalue,  fieldinterp in cursor:recordFields() do
				io.write(string.format("\t\t\t['%s'] = '%s',\n", fieldname, fieldinterp))
			end
			io.write(string.format("\t\t},\n"))

			-- finish out the record
			io.write(string.format("\t},\n"));

		end
	end

	io.write(string.format("}\n"))
end


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

local cursor = AUCursor();

--printTable(cursor);
printRecords(AUCursor())