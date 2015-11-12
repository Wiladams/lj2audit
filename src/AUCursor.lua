local ffi = require("ffi")
local aup = require("auparse_ffi")

local function stringvalue(strptr)
	if strptr == nil then return nil end

	return ffi.string(strptr)
end

local AUCursor = {}
setmetatable(AUCursor, {
	__call = function(self, ...)
		return self:new(...)
	end,
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

function AUCursor.events(self)
	local function gen_events(param, state)

		if not param:nextEvent() then return nil end

		return state + 1, self
	end

	return gen_events, self, 1
end

function AUCursor.numRecords(self)
	return aup.auparse_get_num_records(self.Handle);
end

--[[
	Iterate over the individual records within the event
	that we're currently sitting on.

/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au);
int auparse_next_record(auparse_state_t *au);
int auparse_goto_record_num(auparse_state_t *au, unsigned int num);

/* Accessors to record data */
//int auparse_get_type(auparse_state_t *au);
//const char *auparse_get_type_name(auparse_state_t *au);
//unsigned int auparse_get_line_number(auparse_state_t *au);
//const char *auparse_get_filename(auparse_state_t *au);
int auparse_first_field(auparse_state_t *au);
int auparse_next_field(auparse_state_t *au);
unsigned int auparse_get_num_fields(auparse_state_t *au);
//const char *auparse_get_record_text(auparse_state_t *au);
//const char *auparse_find_field(auparse_state_t *au, const char *name);
//const char *auparse_find_field_next(auparse_state_t *au);


const char *auparse_get_field_name(auparse_state_t *au);
const char *auparse_get_field_str(auparse_state_t *au);
int auparse_get_field_type(auparse_state_t *au);
int auparse_get_field_int(auparse_state_t *au);
const char *auparse_interpret_field(auparse_state_t *au);

--]]



function AUCursor.recordFilename(self)
	local str = aup.auparse_get_filename(self.Handle);
	if str == nil then 
		return nil
	end

	return ffi.string(str)
end

function AUCursor.recordLineNumber(self)
	return aup.auparse_get_line_number(self.Handle)
end

function AUCursor.recordNumFields(self)
	local nFields = aup.auparse_get_num_fields(self.Handle);
	return tonumber(nFields);
end

function AUCursor.recordType(self)
	local rtype = aup.auparse_get_type(self.Handle);

	return rtype;
end


function AUCursor.recordStrings(self)
	local function gen_record(param, state)
		local res = aup.auparse_goto_record_num(param.Handle, state)
		if res < 1 then return nil end

		local rectype = self:recordType();

		local str = aup.auparse_get_record_text(param.Handle);
		if str == nil then return nil end

		return state+1, ffi.string(str)
	end

	-- move to the first record to start
	local res = aup.auparse_first_record(self.Handle)

	return gen_record, self, 0
end

function AUCursor.recordFields(self)
	local function gen_field(param, state)
		local res = aup.auparse_next_field(param.Handle);
		if res < 1 then return nil end

		local fieldname = aup.auparse_get_field_name(param.Handle);
		local fieldvalue = aup.auparse_get_field_str(param.Handle);
		local fieldtype = aup.auparse_get_field_type(param.Handle);
		local fieldinterp = aup.auparse_interpret_field(param.Handle);

		return state+1, stringvalue(fieldname), fieldtype, stringvalue(fieldvalue), stringvalue(fieldinterp)
	end

	return gen_field, self, 1
end


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
