local ffi = require("ffi")

require("platform")

--[[
#include <asm/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/audit.h>
#include <stdarg.h>
#include <syslog.h>
--]]
--[[
/* Audit message types as of 2.6.29 kernel:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 kernel SE Linux use
 * 1500 - 1599 AppArmor events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity labels and related events
 * 1800 - 1999 future kernel use
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2599 user space virtualization management events
 * 2600 - 2999 future user space (maybe integrity labels and related events)
 */
--]]

--[[
	perhaps the entirety of audit.h should be accessible through
	ffi as well, but since the only a few things that 
	are absolutely required in this context, they will be defined here

audit.h
AUDIT_FILTER_TYPE
__AUDIT_ARCH_64BIT 0x80000000
__AUDIT_ARCH_LE	   0x40000000

elf.h
#define EM_PPC64	21		/* PowerPC 64-bit */

--]]


ffi.cdef[[
static const int AUDIT_FILTER_TYPE	= 0x05;	/* Apply rule at audit_log_start */
static const int __AUDIT_ARCH_64BIT = 0x80000000;
static const int __AUDIT_ARCH_LE	= 0x40000000;

static const int EM_PPC64	= 21;		/* PowerPC 64-bit */

]]

ffi.cdef[[
static const int AUDIT_FIRST_USER_MSG   = 1100;    /* First user space message */
static const int AUDIT_LAST_USER_MSG    = 1199;    /* Last user space message */
static const int AUDIT_USER_AUTH        = 1100;    /* User space authentication */
static const int AUDIT_USER_ACCT        = 1101;    /* User space acct change */
static const int AUDIT_USER_MGMT        = 1102;    /* User space acct management */
static const int AUDIT_CRED_ACQ         = 1103;    /* User space credential acquired */
static const int AUDIT_CRED_DISP        = 1104;    /* User space credential disposed */
static const int AUDIT_USER_START       = 1105;    /* User space session start */
static const int AUDIT_USER_END         = 1106;    /* User space session end */
static const int AUDIT_USER_AVC         = 1107;    /* User space avc message */
static const int AUDIT_USER_CHAUTHTOK	=1108;	/* User space acct attr changed */
static const int AUDIT_USER_ERR		=1109;	/* User space acct state err */
static const int AUDIT_CRED_REFR         =1110;    /* User space credential refreshed */
static const int AUDIT_USYS_CONFIG      = 1111;    /* User space system config change */
static const int AUDIT_USER_LOGIN	=1112;    /* User space user has logged in */
static const int AUDIT_USER_LOGOUT	=1113;    /* User space user has logged out */
static const int AUDIT_ADD_USER		=1114;    /* User space user account added */
static const int AUDIT_DEL_USER		=1115;    /* User space user account deleted */
static const int AUDIT_ADD_GROUP		=1116;    /* User space group added */
static const int AUDIT_DEL_GROUP		=1117;    /* User space group deleted */
static const int AUDIT_DAC_CHECK		=1118;    /* User space DAC check results */
static const int AUDIT_CHGRP_ID		=1119;    /* User space group ID changed */
static const int AUDIT_TEST		=1120;	/* Used for test success messages */
static const int AUDIT_TRUSTED_APP	=1121;	/* Trusted app msg - freestyle text */
static const int AUDIT_USER_SELINUX_ERR	=1122;	/* SE Linux user space error */
static const int AUDIT_USER_CMD		=1123;	/* User shell command and args */
static const int AUDIT_USER_TTY		=1124;	/* Non-ICANON TTY input meaning */
static const int AUDIT_CHUSER_ID		=1125;	/* Changed user ID supplemental data */
static const int AUDIT_GRP_AUTH		=1126;	/* Authentication for group password */
static const int AUDIT_SYSTEM_BOOT	=1127;	/* System boot */
static const int AUDIT_SYSTEM_SHUTDOWN	=1128;	/* System shutdown */
static const int AUDIT_SYSTEM_RUNLEVEL	=1129;	/* System runlevel change */
static const int AUDIT_SERVICE_START	=1130;	/* Service (daemon) start */
static const int AUDIT_SERVICE_STOP	=1131;	/* Service (daemon) stop */

static const int AUDIT_FIRST_DAEMON	=1200;
static const int AUDIT_LAST_DAEMON	=1299;
static const int AUDIT_DAEMON_RECONFIG	=1204;	/* Auditd should reconfigure */
static const int AUDIT_DAEMON_ROTATE	=1205;	/* Auditd should rotate logs */
static const int AUDIT_DAEMON_RESUME	=1206;	/* Auditd should resume logging */
static const int AUDIT_DAEMON_ACCEPT	=1207;    /* Auditd accepted remote connection */
static const int AUDIT_DAEMON_CLOSE	=1208;    /* Auditd closed remote connection */

static const int AUDIT_FIRST_EVENT	=1300;
static const int AUDIT_LAST_EVENT	=1399;

static const int AUDIT_FIRST_SELINUX	=1400;
static const int AUDIT_LAST_SELINUX	=1499;

static const int AUDIT_FIRST_APPARMOR		=1500;
static const int AUDIT_LAST_APPARMOR		=1599;

static const int AUDIT_AA			=1500;	/* Not upstream yet */
static const int AUDIT_APPARMOR_AUDIT		=1501;
static const int AUDIT_APPARMOR_ALLOWED		=1502;
static const int AUDIT_APPARMOR_DENIED		=1503;
static const int AUDIT_APPARMOR_HINT		=1504;
static const int AUDIT_APPARMOR_STATUS		=1505;
static const int AUDIT_APPARMOR_ERROR		=1506;


static const int AUDIT_FIRST_KERN_CRYPTO_MSG	=1600;
static const int AUDIT_LAST_KERN_CRYPTO_MSG	=1699;

static const int AUDIT_FIRST_KERN_ANOM_MSG	=1700;
static const int AUDIT_LAST_KERN_ANOM_MSG	=1799;

static const int AUDIT_INTEGRITY_FIRST_MSG	=1800;
static const int AUDIT_INTEGRITY_LAST_MSG	=1899;

static const int AUDIT_INTEGRITY_DATA		=1800; /* Data integrity verification */
static const int AUDIT_INTEGRITY_METADATA 	=1801; // Metadata integrity verification
static const int AUDIT_INTEGRITY_STATUS		=1802; /* Integrity enable status */
static const int AUDIT_INTEGRITY_HASH		=1803; /* Integrity HASH type */
static const int AUDIT_INTEGRITY_PCR		=1804; /* PCR invalidation msgs */
static const int AUDIT_INTEGRITY_RULE		=1805; /* Policy rule */


static const int AUDIT_FIRST_ANOM_MSG		=2100;
static const int AUDIT_LAST_ANOM_MSG		=2199;
static const int AUDIT_ANOM_LOGIN_FAILURES	=2100; // Failed login limit reached
static const int AUDIT_ANOM_LOGIN_TIME		=2101; // Login attempted at bad time
static const int AUDIT_ANOM_LOGIN_SESSIONS	=2102; // Max concurrent sessions reached
static const int AUDIT_ANOM_LOGIN_ACCT		=2103; // Login attempted to watched acct
static const int AUDIT_ANOM_LOGIN_LOCATION	=2104; // Login from forbidden location
static const int AUDIT_ANOM_MAX_DAC		=2105; // Max DAC failures reached
static const int AUDIT_ANOM_MAX_MAC		=2106; // Max MAC failures reached
static const int AUDIT_ANOM_AMTU_FAIL		=2107; // AMTU failure
static const int AUDIT_ANOM_RBAC_FAIL		=2108; // RBAC self test failure
static const int AUDIT_ANOM_RBAC_INTEGRITY_FAIL	=2109; // RBAC file integrity failure
static const int AUDIT_ANOM_CRYPTO_FAIL		=2110; // Crypto system test failure
static const int AUDIT_ANOM_ACCESS_FS		=2111; // Access of file or dir
static const int AUDIT_ANOM_EXEC			=2112; // Execution of file
static const int AUDIT_ANOM_MK_EXEC		=2113; // Make an executable
static const int AUDIT_ANOM_ADD_ACCT		=2114; // Adding an acct
static const int AUDIT_ANOM_DEL_ACCT		=2115; // Deleting an acct
static const int AUDIT_ANOM_MOD_ACCT		=2116; // Changing an acct
static const int AUDIT_ANOM_ROOT_TRANS		=2117; // User became root

static const int AUDIT_FIRST_ANOM_RESP		=2200;
static const int AUDIT_LAST_ANOM_RESP		=2299;
static const int AUDIT_RESP_ANOMALY		=2200; /* Anomaly not reacted to */
static const int AUDIT_RESP_ALERT		=2201; /* Alert email was sent */
static const int AUDIT_RESP_KILL_PROC		=2202; /* Kill program */
static const int AUDIT_RESP_TERM_ACCESS		=2203; /* Terminate session */
static const int AUDIT_RESP_ACCT_REMOTE		=2204; /* Acct locked from remote access*/
static const int AUDIT_RESP_ACCT_LOCK_TIMED	=2205; /* User acct locked for time */
static const int AUDIT_RESP_ACCT_UNLOCK_TIMED	=2206; /* User acct unlocked from time */
static const int AUDIT_RESP_ACCT_LOCK		=2207; /* User acct was locked */
static const int AUDIT_RESP_TERM_LOCK		=2208; /* Terminal was locked */
static const int AUDIT_RESP_SEBOOL		=2209; /* Set an SE Linux boolean */
static const int AUDIT_RESP_EXEC			=2210; /* Execute a script */
static const int AUDIT_RESP_SINGLE		=2211; /* Go to single user mode */
static const int AUDIT_RESP_HALT			=2212; /* take the system down */

static const int AUDIT_FIRST_USER_LSPP_MSG	=2300;
static const int AUDIT_LAST_USER_LSPP_MSG	=2399;
static const int AUDIT_USER_ROLE_CHANGE		=2300; /* User changed to a new role */
static const int AUDIT_ROLE_ASSIGN		=2301; /* Admin assigned user to role */
static const int AUDIT_ROLE_REMOVE		=2302; /* Admin removed user from role */
static const int AUDIT_LABEL_OVERRIDE		=2303; /* Admin is overriding a label */
static const int AUDIT_LABEL_LEVEL_CHANGE	=2304; /* Object's level was changed */
static const int AUDIT_USER_LABELED_EXPORT	=2305; /* Object exported with label */
static const int AUDIT_USER_UNLABELED_EXPORT	=2306; /* Object exported without label */
static const int AUDIT_DEV_ALLOC			=2307; /* Device was allocated */
static const int AUDIT_DEV_DEALLOC		=2308; /* Device was deallocated */
static const int AUDIT_FS_RELABEL		=2309; /* Filesystem relabeled */
static const int AUDIT_USER_MAC_POLICY_LOAD	=2310; /* Userspc daemon loaded policy */
static const int AUDIT_ROLE_MODIFY		=2311; /* Admin modified a role */
static const int AUDIT_USER_MAC_CONFIG_CHANGE	=2312; /* Change made to MAC policy */

static const int AUDIT_FIRST_CRYPTO_MSG		=2400;
static const int AUDIT_CRYPTO_TEST_USER		=2400; /* Crypto test results */
static const int AUDIT_CRYPTO_PARAM_CHANGE_USER	=2401; /* Crypto attribute change */
static const int AUDIT_CRYPTO_LOGIN			=2402; /* Logged in as crypto officer */
static const int AUDIT_CRYPTO_LOGOUT		=2403; /* Logged out from crypto */
static const int AUDIT_CRYPTO_KEY_USER		=2404; /* Create,delete,negotiate */
static const int AUDIT_CRYPTO_FAILURE_USER	=2405; /* Fail decrypt,encrypt,randomiz */
static const int AUDIT_CRYPTO_REPLAY_USER	=2406; /* Crypto replay detected */
static const int AUDIT_CRYPTO_SESSION		=2407; /* Record parameters set during
						TLS session establishment */

static const int AUDIT_LAST_CRYPTO_MSG		=2499;

static const int AUDIT_FIRST_VIRT_MSG		=2500;
static const int AUDIT_VIRT_CONTROL			=2500; /* Start, Pause, Stop VM */
static const int AUDIT_VIRT_RESOURCE		=2501; /* Resource assignment */
static const int AUDIT_VIRT_MACHINE_ID		=2502; /* Binding of label to VM */

static const int AUDIT_LAST_VIRT_MSG		=2599;
]]


ffi.cdef[[
static const int AUDIT_FIRST_USER_MSG2  =2100;    /* More userspace messages */
static const int AUDIT_LAST_USER_MSG2   =2999;

/* New kernel event definitions since 2.6.30 */
static const int AUDIT_MMAP				=1323; /* Descriptor and flags in mmap */

static const int AUDIT_NETFILTER_PKT	=1324; /* Packets traversing netfilter chains */
static const int AUDIT_NETFILTER_CFG	=1325; /* Netfilter chain modifications */
static const int AUDIT_SECCOMP			=1326; /* Secure Computing event */
static const int AUDIT_PROCTITLE		=1327; /* Process Title info */
static const int AUDIT_FEATURE_CHANGE	=1328; /* Audit feature changed value */
static const int AUDIT_ANOM_LINK		=1702; /* Suspicious use of file links */

/* This is related to the filterkey patch */
static const int AUDIT_KEY_SEPARATOR 	=0x01;

/* These are used in filter control */
static const int AUDIT_FILTER_EXCLUDE	= AUDIT_FILTER_TYPE;
static const int AUDIT_FILTER_MASK		= 0x07;	/* Mask to get actual filter */
static const int AUDIT_FILTER_UNSET		= 0x80;	/* This value means filter is unset */
]]

ffi.cdef[[
/* Defines for interfield comparison update */
static const int AUDIT_OBJ_UID  = 109;
static const int AUDIT_OBJ_GID  = 110;
static const int AUDIT_FIELD_COMPARE = 111;

static const int AUDIT_COMPARE_UID_TO_OBJ_UID  = 1;
static const int AUDIT_COMPARE_GID_TO_OBJ_GID  = 2;
static const int AUDIT_COMPARE_EUID_TO_OBJ_UID = 3;
static const int AUDIT_COMPARE_EGID_TO_OBJ_GID = 4;
static const int AUDIT_COMPARE_AUID_TO_OBJ_UID = 5;
static const int AUDIT_COMPARE_SUID_TO_OBJ_UID = 6;
static const int AUDIT_COMPARE_SGID_TO_OBJ_GID = 7;
static const int AUDIT_COMPARE_FSUID_TO_OBJ_UID= 8;
static const int AUDIT_COMPARE_FSGID_TO_OBJ_GID= 9;
static const int AUDIT_COMPARE_UID_TO_AUID     = 10;
static const int AUDIT_COMPARE_UID_TO_EUID     = 11;
static const int AUDIT_COMPARE_UID_TO_FSUID    = 12;
static const int AUDIT_COMPARE_UID_TO_SUID     = 13;
static const int AUDIT_COMPARE_AUID_TO_FSUID   = 14;
static const int AUDIT_COMPARE_AUID_TO_SUID    = 15;
static const int AUDIT_COMPARE_AUID_TO_EUID    = 16;
static const int AUDIT_COMPARE_EUID_TO_SUID    = 17;
static const int AUDIT_COMPARE_EUID_TO_FSUID   = 18;
static const int AUDIT_COMPARE_SUID_TO_FSUID   = 19;
static const int AUDIT_COMPARE_GID_TO_EGID     = 20;
static const int AUDIT_COMPARE_GID_TO_FSGID    = 21;
static const int AUDIT_COMPARE_GID_TO_SGID     = 22;
static const int AUDIT_COMPARE_EGID_TO_FSGID   = 23;
static const int AUDIT_COMPARE_EGID_TO_SGID    = 24;
static const int AUDIT_COMPARE_SGID_TO_FSGID   = 25;

static const int EM_ARM  = 40;
static const int EM_AARCH64 = 183;

static const int AUDIT_ARCH_AARCH64	= (EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_PPC64LE	= (EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
]]

ffi.cdef[[
//////////////////////////////////////////////////////
// This is an external ABI. Any changes in here will
// likely affect pam_loginuid. There might be other
// apps that use this low level interface, but I don't
// know of any.
//
/* data structure for who signaled the audit daemon */
struct audit_sig_info {
        uid_t           uid;
        pid_t           pid;
	char		ctx[0];
};

/* defines for audit subsystem */
static const int MAX_AUDIT_MESSAGE_LENGTH    = 8970; // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
struct audit_message {
	struct nlmsghdr nlh;
	char   data[MAX_AUDIT_MESSAGE_LENGTH];
};

// internal - forward declaration
struct daemon_conf;

struct audit_reply {
	int                      type;
	int                      len;
	struct nlmsghdr         *nlh;
	struct audit_message     msg;

	/* Using a union to compress this structure since only one of
	 * the following should be valid for any packet. */
	union {
	struct audit_status     *status;
	struct audit_rule_data  *ruledata;
	struct audit_login      *login;
	const char              *message;
	struct nlmsgerr         *error;
	struct audit_sig_info   *signal_info;
	struct daemon_conf      *conf;
	};
};

//
// End of ABI control
//////////////////////////////////////////////////////
]]

ffi.cdef[[
//////////////////////////////////////////////////////
// audit dispatcher interface
//
/* audit_dispatcher_header: This header is versioned. If anything gets
 * added to it, it must go at the end and the version number bumped.
 * This MUST BE fixed size for compatibility. If you are going to add
 * new member then add them into _structure_ part.
 */
struct audit_dispatcher_header {
	uint32_t	ver;	/* The version of this protocol */
	uint32_t	hlen;	/* Header length */
	uint32_t	type;	/* Message type */
	uint32_t	size;	/* Size of data following the header */
};

static const int AUDISP_PROTOCOL_VER = 0;
]]

ffi.cdef[[
///////////////////////////////////////////////////
// Libaudit API
//

/* This is the machine type list */
typedef enum {
	MACH_X86=0,
	MACH_86_64,
	MACH_IA64,
	MACH_PPC64,
	MACH_PPC,
	MACH_S390X,
	MACH_S390,
	MACH_ALPHA,
	MACH_ARM,
	MACH_AARCH64,
	MACH_PPC64LE
} machine_t;

/* These are the valid audit failure tunable enum values */
typedef enum {
	FAIL_IGNORE=0,
	FAIL_LOG,
	FAIL_TERMINATE
} auditfail_t;

/* Messages */
typedef enum { MSG_STDERR, MSG_SYSLOG, MSG_QUIET } message_t;
typedef enum { DBG_NO, DBG_YES } debug_message_t;
void set_aumessage_mode(message_t mode, debug_message_t debug);
]]

ffi.cdef[[
/* General */
typedef enum { GET_REPLY_BLOCKING=0, GET_REPLY_NONBLOCKING } reply_t;
extern int  audit_open(void);
extern void audit_close(int fd);
extern int  audit_get_reply(int fd, struct audit_reply *rep, reply_t block, 
		int peek);
extern uid_t audit_getloginuid(void);
extern int  audit_setloginuid(uid_t uid);
extern int  audit_detect_machine(void);
extern int audit_determine_machine(const char *arch);

/* Translation functions */
extern int        audit_name_to_field(const char *field);
extern const char *audit_field_to_name(int field);
extern int        audit_name_to_syscall(const char *sc, int machine);
extern const char *audit_syscall_to_name(int sc, int machine);
extern int        audit_name_to_flag(const char *flag);
extern const char *audit_flag_to_name(int flag);
extern int        audit_name_to_action(const char *action);
extern const char *audit_action_to_name(int action);
extern int        audit_name_to_msg_type(const char *msg_type);
extern const char *audit_msg_type_to_name(int msg_type);
extern int        audit_name_to_machine(const char *machine);
extern const char *audit_machine_to_name(int machine);
extern unsigned int audit_machine_to_elf(int machine);
extern int          audit_elf_to_machine(unsigned int elf);
extern const char *audit_operator_to_symbol(int op);
extern int        audit_name_to_errno(const char *error);
extern const char *audit_errno_to_name(int error);
extern int        audit_name_to_ftype(const char *name);
extern const char *audit_ftype_to_name(int ftype); 
extern void audit_number_to_errmsg(int errnumber, const char *opt);
]]

ffi.cdef[[
/* AUDIT_GET */
extern int audit_request_status(int fd);
extern int audit_is_enabled(int fd);
extern int get_auditfail_action(auditfail_t *failmode);
]]

ffi.cdef[[
/* AUDIT_SET */
typedef enum { WAIT_NO, WAIT_YES } rep_wait_t;
extern int  audit_set_pid(int fd, uint32_t pid, rep_wait_t wmode);
extern int  audit_set_enabled(int fd, uint32_t enabled);
extern int  audit_set_failure(int fd, uint32_t failure);
extern int  audit_set_rate_limit(int fd, uint32_t limit);
extern int  audit_set_backlog_limit(int fd, uint32_t limit);
]]

ffi.cdef[[
/* AUDIT_LIST_RULES */
extern int  audit_request_rules_list_data(int fd);
]]

ffi.cdef[[
/* SIGNAL_INFO */
extern int audit_request_signal_info(int fd);
]]

ffi.cdef[[
/* AUDIT_WATCH */
extern int audit_update_watch_perms(struct audit_rule_data *rule, int perms);
extern int audit_add_watch(struct audit_rule_data **rulep, const char *path);
extern int audit_add_dir(struct audit_rule_data **rulep, const char *path);
extern int audit_add_watch_dir(int type, struct audit_rule_data **rulep,
				const char *path);
extern int audit_trim_subtrees(int fd);
extern int audit_make_equivalent(int fd, const char *mount_point,
				const char *subtree);
]]

ffi.cdef[[
/* AUDIT_ADD_RULE */
extern int  audit_add_rule_data(int fd, struct audit_rule_data *rule,
                                int flags, int action);
]]

ffi.cdef[[
/* AUDIT_DEL_RULE */
extern int  audit_delete_rule_data(int fd, struct audit_rule_data *rule,
                                   int flags, int action);
]]

ffi.cdef[[
/* The following are for standard formatting of messages */
extern int audit_value_needs_encoding(const char *str, unsigned int len);
extern char *audit_encode_value(char *final,const char *buf,unsigned int size);
extern char *audit_encode_nv_string(const char *name, const char *value,
	unsigned int vlen);
extern int audit_log_user_message(int audit_fd, int type, const char *message,
        const char *hostname, const char *addr, const char *tty, int result);
extern int audit_log_user_comm_message(int audit_fd, int type,
	const char *message, const char *comm, const char *hostname,
	const char *addr, const char *tty, int result);
extern int audit_log_acct_message(int audit_fd, int type, const char *pgname,
        const char *op, const char *name, unsigned int id,
        const char *host, const char *addr, const char *tty, int result);
extern int audit_log_user_avc_message(int audit_fd, int type, 
	const char *message, const char *hostname, const char *addr, 
	const char *tty, uid_t uid);
extern int audit_log_semanage_message(int audit_fd, int type,
	const char *pgname, const char *op, const char *name, unsigned int id,
        const char *new_seuser, const char *new_role, const char *new_range,
	const char *old_seuser, const char *old_role, const char *old_range,
	const char *host, const char *addr,
        const char *tty, int result);
extern int audit_log_user_command(int audit_fd, int type, const char *command,
        const char *tty, int result);

/* Rule-building helper functions */
extern int  audit_rule_syscall_data(struct audit_rule_data *rule, int scall);
extern int  audit_rule_syscallbyname_data(struct audit_rule_data *rule,
                                          const char *scall);
/* Note that the following function takes a **, where audit_rule_fieldpair()
 * takes just a *.  That structure may need to be reallocated as a result of
 * adding new fields */
extern int  audit_rule_fieldpair_data(struct audit_rule_data **rulep,
                                      const char *pair, int flags);
extern int audit_rule_interfield_comp_data(struct audit_rule_data **rulep,
					 const char *pair, int flags);
extern void audit_rule_free_data(struct audit_rule_data *rule);
]]

local Lib_audit = ffi.load("audit")

local exports = {
	Lib_audit = Lib_audit;
}
setmetatable(exports, {
	__index = function(self, key)
		local value = nil;
		local success = false;


		-- try looking in the library for a function
		success, value = pcall(function() return Lib_audit[key] end)
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
