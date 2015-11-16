local ffi = require("ffi")
local aup = require("lj2audit.auparse_ffi")

local stringvalue = aup.stringvalue;

local AURecord = {}
local AURecord_mt = {
	__index = AURecord,

	__tostring = function(self)
		return self:toString();
	end,
}

function AURecord.recordFilename(self)
	local str = aup.auparse_get_filename(self.Handle);
	if str == nil then 
		return nil
	end

	return ffi.string(str)
end

function AURecord.recordLineNumber(self)
	return aup.auparse_get_line_number(self.Handle)
end

function AURecord.recordNumFields(self)
	local nFields = aup.auparse_get_num_fields(self.Handle);
	return tonumber(nFields);
end

function AURecord.recordType(self)
	local rtype = aup.auparse_get_type(self.Handle);

	return rtype;
end

function AURecord.toString(self)
	local str = aup.auparse_get_record_text(self.Handle);
	if str == nil then return nil end

	return ffi.string(str);
end

--[[
	Iterate
--]]
function AURecord.recordFields(self)
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

return AURecord
