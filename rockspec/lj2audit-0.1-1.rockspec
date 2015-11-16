 package = "lj2audit"
 version = "0.1-1"
 source = {
    url = "https://github.com/wiladams/lj2audit/archive/v0.1-1.tar.gz",
    dir = "lj2audit-0.1-1",
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
      ["lj2audit.fun"] = "src/fun.lua",

      -- platform specifics
      ["lj2audit.audit"] = "src/audit.lua",
      ["lj2audit.auparse_ffi"] = "src/auparse_ffi.lua",
      ["lj2audit.elf-em"] = "src/elf-em.lua",
      ["lj2audit.libaudit_ffi"] = "src/libaudit_ffi.lua",
      ["lj2audit.platform"] = "src/platform.lua",

      -- class-like interfaces
      ["lj2audit.AUCursor"] = "src/AUCursor.lua",
      ["lj2audit.AURecord"] = "src/AURecord.lua"
    },

 }
