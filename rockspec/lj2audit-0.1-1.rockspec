 package = "lj2audit"
 version = "0.1-2"
 source = {
    url = "https://github.com/wiladams/lj2audit/archive/v0.1-2.tar.gz",
    dir = "lj2audit-0.1-2",
 }
 description = {
    summary = "Interacting with Linux auditd from LuaJIT",
    detailed = [[
       The auditing capabilities in the Linux kernel can be exposed
       using the auditd daemon, and attendant utilities.  This binding
       gives access to the libauparse, and libaudit libraries, and all 
       the functions therein.
    ]],
    homepage = "http://github.com/wiladams/lj2audit",
    license = "MIT/X11"
 }
 dependencies = {
    "lua ~> 5.1"
 }
 build = {
    type = "builtin",

    modules = {
      -- general programming goodness
      ["lj2audit.fun"] = "lj2audit/fun.lua",

      -- platform specifics
      ["lj2audit.audit"] = "lj2audit/audit.lua",
      ["lj2audit.auparse_ffi"] = "lj2audit/auparse_ffi.lua",
      ["lj2audit.elf-em"] = "lj2audit/elf-em.lua",
      ["lj2audit.libaudit_ffi"] = "lj2audit/libaudit_ffi.lua",
      ["lj2audit.platform"] = "lj2audit/platform.lua",

      -- class-like interfaces
      ["lj2audit.AUCursor"] = "lj2audit/AUCursor.lua",
      ["lj2audit.AURecord"] = "lj2audit/AURecord.lua"
    },

 }
