

local ffi = require("ffi")
require("platform")


ffi.cdef[[
/* Library type definitions */

/* This tells the library where the data source is located */
typedef enum { 
	AUSOURCE_LOGS, 
	AUSOURCE_FILE, 
	AUSOURCE_FILE_ARRAY, 
	AUSOURCE_BUFFER, 
	AUSOURCE_BUFFER_ARRAY,
	AUSOURCE_DESCRIPTOR, 
	AUSOURCE_FILE_POINTER, 
	AUSOURCE_FEED 
} ausource_t;

/* This used to define the types of searches that can be done.  It is not used
   any more. */
typedef enum {
	AUSEARCH_UNSET,
	AUSEARCH_EXISTS,
	AUSEARCH_EQUAL, AUSEARCH_NOT_EQUAL,
	AUSEARCH_TIME_LT, AUSEARCH_TIME_LE, AUSEARCH_TIME_GE, AUSEARCH_TIME_GT,
	AUSEARCH_TIME_EQ,
	AUSEARCH_INTERPRETED = 0x40000000
} ausearch_op_t;

/* This determines where to position the cursor when a search completes */
typedef enum { AUSEARCH_STOP_EVENT, AUSEARCH_STOP_RECORD,
	AUSEARCH_STOP_FIELD } austop_t;

/* This defines how search rule pieces are treated to decide when
 * to stop a search */
typedef enum { AUSEARCH_RULE_CLEAR, AUSEARCH_RULE_OR,
        AUSEARCH_RULE_AND, AUSEARCH_RULE_REGEX } ausearch_rule_t;


typedef struct
{
        time_t sec;             // Event seconds
        unsigned int milli;     // millisecond of the timestamp
        unsigned long serial;   // Serial number of the event
	const char *host;	// Machine's name
} au_event_t;


/* This indicates why the user supplied callback was invoked */
typedef enum {AUPARSE_CB_EVENT_READY} auparse_cb_event_t;

/* This determines the type of field at current cursor location
 * ONLY APPEND - DO NOT DELETE or it will break ABI */
typedef enum {  AUPARSE_TYPE_UNCLASSIFIED,  AUPARSE_TYPE_UID, AUPARSE_TYPE_GID,
	AUPARSE_TYPE_SYSCALL, AUPARSE_TYPE_ARCH, AUPARSE_TYPE_EXIT,
	AUPARSE_TYPE_ESCAPED, AUPARSE_TYPE_PERM, AUPARSE_TYPE_MODE,
	AUPARSE_TYPE_SOCKADDR, AUPARSE_TYPE_FLAGS, AUPARSE_TYPE_PROMISC,
	AUPARSE_TYPE_CAPABILITY, AUPARSE_TYPE_SUCCESS, AUPARSE_TYPE_A0,
	AUPARSE_TYPE_A1, AUPARSE_TYPE_A2, AUPARSE_TYPE_A3, AUPARSE_TYPE_SIGNAL, 
	AUPARSE_TYPE_LIST, AUPARSE_TYPE_TTY_DATA,
	AUPARSE_TYPE_SESSION, AUPARSE_TYPE_CAP_BITMAP, AUPARSE_TYPE_NFPROTO,
	AUPARSE_TYPE_ICMPTYPE, AUPARSE_TYPE_PROTOCOL,
	AUPARSE_TYPE_ADDR, AUPARSE_TYPE_PERSONALITY,
	AUPARSE_TYPE_SECCOMP, AUPARSE_TYPE_OFLAG,
	AUPARSE_TYPE_MMAP, AUPARSE_TYPE_MODE_SHORT, AUPARSE_TYPE_MAC_LABEL  } auparse_type_t;
]]


ffi.cdef[[
/* Library type definitions */

/* opaque data type used for maintaining library state */
typedef struct opaque auparse_state_t;

typedef void (*user_destroy)(void *user_data);
typedef void (*auparse_callback_ptr)(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data);
]]

ffi.cdef[[
/* General functions that affect operation of the library */
auparse_state_t *auparse_init(ausource_t source, const void *b);
int auparse_feed(auparse_state_t *au, const char *data, size_t data_len);
int auparse_flush_feed(auparse_state_t *au);
int auparse_feed_has_data(const auparse_state_t *au);
void auparse_add_callback(auparse_state_t *au, auparse_callback_ptr callback,
			void *user_data, user_destroy user_destroy_func);
int auparse_reset(auparse_state_t *au);
void auparse_destroy(auparse_state_t *au);

/* Functions that are part of the search interface */
int ausearch_add_expression(auparse_state_t *au, const char *expression,
			    char **error, ausearch_rule_t how);
int ausearch_add_item(auparse_state_t *au, const char *field, const char *op,
			const char *value, ausearch_rule_t how);
int ausearch_add_interpreted_item(auparse_state_t *au, const char *field,
			const char *op, const char *value, ausearch_rule_t how);
int ausearch_add_timestamp_item(auparse_state_t *au, const char *op, time_t sec,
				unsigned milli, ausearch_rule_t how);
int ausearch_add_regex(auparse_state_t *au, const char *expr);
int ausearch_set_stop(auparse_state_t *au, austop_t where);
void ausearch_clear(auparse_state_t *au);

/* Functions that traverse events */
int ausearch_next_event(auparse_state_t *au);
int auparse_next_event(auparse_state_t *au);

/* Accessors to event data */
const au_event_t *auparse_get_timestamp(auparse_state_t *au);
time_t auparse_get_time(auparse_state_t *au);
unsigned int auparse_get_milli(auparse_state_t *au);
unsigned long auparse_get_serial(auparse_state_t *au);
const char *auparse_get_node(auparse_state_t *au);
int auparse_node_compare(au_event_t *e1, au_event_t *e2);
int auparse_timestamp_compare(au_event_t *e1, au_event_t *e2);
unsigned int auparse_get_num_records(auparse_state_t *au);

/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au);
int auparse_next_record(auparse_state_t *au);
int auparse_goto_record_num(auparse_state_t *au, unsigned int num);

/* Accessors to record data */
int auparse_get_type(auparse_state_t *au);
const char *auparse_get_type_name(auparse_state_t *au);
unsigned int auparse_get_line_number(auparse_state_t *au);
const char *auparse_get_filename(auparse_state_t *au);
int auparse_first_field(auparse_state_t *au);
int auparse_next_field(auparse_state_t *au);
unsigned int auparse_get_num_fields(auparse_state_t *au);
const char *auparse_get_record_text(auparse_state_t *au);
const char *auparse_find_field(auparse_state_t *au, const char *name);
const char *auparse_find_field_next(auparse_state_t *au);

/* Accessors to field data */
const char *auparse_get_field_name(auparse_state_t *au);
const char *auparse_get_field_str(auparse_state_t *au);
int auparse_get_field_type(auparse_state_t *au);
int auparse_get_field_int(auparse_state_t *au);
const char *auparse_interpret_field(auparse_state_t *au);
]]


local Lib_auparse = ffi.load("auparse")

local exports = {
	Lib_auparse = Lib_auparse;
}
setmetatable(exports, {
	__index = function(self, key)
		local value = nil;
		local success = false;


		-- try looking in the library for a function
		success, value = pcall(function() return Lib_auparse[key] end)
		if success then
			rawset(self, key, value);
			return value;
		end

		-- try looking in the ffi.C namespace, for constants
		-- and enums
		success, value = pcall(function() return ffi.C[key] end)
		if success then
			rawset(self, key, value);
			return value;
		end

		-- Or maybe it's a type
		success, value = pcall(function() return ffi.typeof(key) end)
		if success then
			rawset(self, key, value);
			return value;
		end

		return nil;
	end,
})

return exports
