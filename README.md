# lj2audit
LuaJIT binding to libaudit for linux auditing

The Linux OS has some auditing capabilities built into the kernel.  Any application can make the necessary
calls to gain access to those features.  The auditd daemon is one such program that provides relatively 
convenient user space access to the kernel audit features.

The auditd daemon has two support libraries, libauparse.so, and libaudit.so.  These two libraries are what
this binding is all about.  Between them, you can either configure auditing, or you can read the ongoing
autdit events (libauparse).

As is usual for this kind of binding, it can operate at two levels.  The lowest level provides an 
interface which is fairly faithful to the original 'C' interface.  Here is a simple example of getting 
a cursor opened, and moving to the next entry:

NOTE: Running these commands requires root access, so running with 'sudo' is likely required.

```lua
local ffi = require("ffi")
local aup = require("auparse_ffi")

local cursor = aup.auparse_init(aup.AUSOURCE_LOGS, nil);

assert(cursor ~= nil, "auparse_init() failure")

ffi.gc(cursor, aup.auparse_destroy)

-- move to the next event
local res = aup.auparse_next_event(cursor);
```

This is pretty much exactly what you would do in C, with the exception of using ffi.gc() to 
cleanup the opened cursor when it leaves scope.

At the next level, there is a more Lua like interface, which supports various lua idioms, such as
tables, iterators, strings, and the like.  Here is an example of using the basics of that interface.

```lua
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
```

In this case, the AUCursor object is used, which has an iterator interface 'events()', for getting
at the stream of events.  As the cursor moves along, it also has an iterator 'records()'
which gives you access to individual records within a single event.  Each individual record is represented
as a table, and one of the values within the table is the 'fields' table, which contains the actual parsed out field values for the record.

Here's one more example, which shows how to iterate over the records, and generate a printout in lua 
form of the data.

```lua
local AUCursor = require("AUCursor")
local fun = require("fun")


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
```

The libauparser library is capable of reading data from various sources.  In the above cases, the default
is to read data from existing log files.  Another case is to read the data from the live running system.
This capability already exists in the current implementation, although it's not taylored for that case, so 
it needs some more work to make it viable.

INSTALLING
----------
Required packages (Ubuntu)
* sudo apt-get install libauparse-dev
* sudo apt-get install libaudit-dev
* sudo apt-get install auditd

