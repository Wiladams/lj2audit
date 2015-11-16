local ffi = require("ffi")
local aup = require("lj2audit.auparse_ffi")
local AURecord = require("lj2audit.AURecord")

local stringvalue = aup.stringvalue;


local AUCursor = {}
setmetatable(AUCursor, {
	__call = function(self, ...)
		return self:new(...)
	end,

	__index = AURecord;
})

local AUCursor_mt = {
	__index = AUCursor;
}

function AUCursor.init(self, handle)
	local obj = {
		Handle = handle
	}
	setmetatable(obj, AUCursor_mt)

	return obj;
end

function AUCursor.new(self, flags)
	flags = flags or aup.AUSOURCE_LOGS;
	local handle = aup.auparse_init(flags, nil);
	
	if handle == nil then return nil end

	-- leverage the gc to cleanup the handle 
	-- when it is out of scope.
	ffi.gc(handle, aup.auparse_destroy)

	return self:init(handle);
end

--[[
	Move to the next entry.  Each event is composed of 
	1 or more records.  So, once you call nextEvent(),
	you can use the records() iterator to iterate over
	individual records.

	The auparse_next_event() call returns the following
	-1 == error
	 0 == no more entries
	 1 == OK
--]]
function AUCursor.nextEvent(self)
	local res = aup.auparse_next_event(self.Handle);

	return res > 0
end

-- iterate over all the events
function AUCursor.events(self)
	local function gen_events(param, state)

		if not param:nextEvent() then return nil end

		return state + 1, self
	end

	return gen_events, self, 1
end

-- Return the number of records that can be found
-- within the current event.
function AUCursor.numRecords(self)
	return aup.auparse_get_num_records(self.Handle);
end



--[[
	Iterate over the individual records within the event
	that we're currently sitting on.
--]]
function AUCursor.records(self)
	local function gen_record(param, state)
		local res = aup.auparse_goto_record_num(param.Handle, state)
		if res < 1 then return nil end

		local tbl = {
			recordFilename = param:recordFilename();
			recordLineNumber = param:recordLineNumber();
			recordType = param:recordType();
			recordNumberOfFields = param:recordNumFields();
		}

		--local str = aup.auparse_get_record_text(param.Handle);

		tbl.fields = {};
		for _, fieldname, fieldtype, fieldvalue,  fieldinterp in param:recordFields() do
			tbl.fields[fieldname] = fieldinterp
		end

		return state+1, tbl
	end

	-- move to the first record to start
	--local res = aup.auparse_first_record(self.Handle)

	return gen_record, self, 0
end



return AUCursor;
