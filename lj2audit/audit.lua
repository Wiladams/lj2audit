
local ffi = require("ffi")

require ("lj2audit.elf-em")




ffi.cdef[[
static const int AUDIT_GET		=1000;	/* Get status */
static const int AUDIT_SET		=1001;	/* Set status (enable/disable/auditd) */
static const int AUDIT_LIST		=1002;	/* List syscall rules -- deprecated */
static const int AUDIT_ADD		=1003;	/* Add syscall rule -- deprecated */
static const int AUDIT_DEL		=1004;	/* Delete syscall rule -- deprecated */
static const int AUDIT_USER		=1005;	/* Message from userspace -- deprecated */
static const int AUDIT_LOGIN		=1006;	/* Define the login id and information */
static const int AUDIT_WATCH_INS		=1007;	/* Insert file/dir watch entry */
static const int AUDIT_WATCH_REM		=1008;	/* Remove file/dir watch entry */
static const int AUDIT_WATCH_LIST	=1009;	/* List all file/dir watches */
static const int AUDIT_SIGNAL_INFO	=1010;	/* Get info about sender of signal to auditd */
static const int AUDIT_ADD_RULE		=1011;	/* Add syscall filtering rule */
static const int AUDIT_DEL_RULE		=1012;	/* Delete syscall filtering rule */
static const int AUDIT_LIST_RULES	=1013;	/* List syscall filtering rules */
static const int AUDIT_TRIM		=1014;	/* Trim junk from watched tree */
static const int AUDIT_MAKE_EQUIV	=1015;	/* Append to watched tree */
static const int AUDIT_TTY_GET		=1016;	/* Get TTY auditing status */
static const int AUDIT_TTY_SET		=1017;	/* Set TTY auditing status */
static const int AUDIT_SET_FEATURE	=1018;	/* Turn an audit feature on or off */
static const int AUDIT_GET_FEATURE	=1019;	/* Get which features are enabled */
]]

ffi.cdef[[
static const int AUDIT_FIRST_USER_MSG	=1100;	/* Userspace messages mostly uninteresting to kernel */
static const int AUDIT_USER_AVC		=1107;	/* We filter this differently */
static const int AUDIT_USER_TTY		=1124;	/* Non-ICANON TTY input meaning */
static const int AUDIT_LAST_USER_MSG	=1199;
static const int AUDIT_FIRST_USER_MSG2	=2100;	/* More user space messages */
static const int AUDIT_LAST_USER_MSG2	=2999;
]]

ffi.cdef[[
static const int AUDIT_DAEMON_START      =1200;    /* Daemon startup record */
static const int AUDIT_DAEMON_END        =1201;   /* Daemon normal stop record */
static const int AUDIT_DAEMON_ABORT      =1202;    /* Daemon error stop record */
static const int AUDIT_DAEMON_CONFIG     =1203;    /* Daemon config change */
]]

ffi.cdef[[
static const int AUDIT_SYSCALL		=1300;	/* Syscall event */
/* static const int AUDIT_FS_WATCH	=1301;	 * Deprecated */
static const int AUDIT_PATH		=1302;	/* Filename path information */
static const int AUDIT_IPC		=1303;	/* IPC record */
static const int AUDIT_SOCKETCALL	=1304;	/* sys_socketcall arguments */
static const int AUDIT_CONFIG_CHANGE	=1305;	/* Audit system configuration change */
static const int AUDIT_SOCKADDR		=1306;	/* sockaddr copied as syscall arg */
static const int AUDIT_CWD		=1307;	/* Current working directory */
static const int AUDIT_EXECVE		=1309;	/* execve arguments */
static const int AUDIT_IPC_SET_PERM	=1311;	/* IPC new permissions record type */
static const int AUDIT_MQ_OPEN		=1312;	/* POSIX MQ open record type */
static const int AUDIT_MQ_SENDRECV	=1313;	/* POSIX MQ send/receive record type */
static const int AUDIT_MQ_NOTIFY		=1314;	/* POSIX MQ notify record type */
static const int AUDIT_MQ_GETSETATTR	=1315;	/* POSIX MQ get/set attribute record type */
static const int AUDIT_KERNEL_OTHER	=1316;	/* For use by 3rd party modules */
static const int AUDIT_FD_PAIR		=1317;    /* audit record for pipe/socketpair */
static const int AUDIT_OBJ_PID		=1318;	/* ptrace target */
static const int AUDIT_TTY		=1319;	/* Input on an administrative TTY */
static const int AUDIT_EOE		=1320;	/* End of multi-record event */
static const int AUDIT_BPRM_FCAPS	=1321;	/* Information about fcaps increasing perms */
static const int AUDIT_CAPSET		=1322;	/* Record showing argument to sys_capset */
static const int AUDIT_MMAP		=1323;	/* Record showing descriptor and flags in mmap */
static const int AUDIT_NETFILTER_PKT	=1324;	/* Packets traversing netfilter chains */
static const int AUDIT_NETFILTER_CFG	=1325;	/* Netfilter chain modifications */
static const int AUDIT_SECCOMP		=1326;	/* Secure Computing event */
static const int AUDIT_PROCTITLE		=1327;	/* Proctitle emit event */
static const int AUDIT_FEATURE_CHANGE	=1328;	/* audit log listing feature changes */
]]

ffi.cdef[[
static const int AUDIT_AVC		=1400;	/* SE Linux avc denial or grant */
static const int AUDIT_SELINUX_ERR	=1401;	/* Internal SE Linux Errors */
static const int AUDIT_AVC_PATH		=1402;	/* dentry, vfsmount pair from avc */
static const int AUDIT_MAC_POLICY_LOAD	=1403;	/* Policy file load */
static const int AUDIT_MAC_STATUS	=1404;	/* Changed enforcing,permissive,off */
static const int AUDIT_MAC_CONFIG_CHANGE	=1405;	/* Changes to booleans */
static const int AUDIT_MAC_UNLBL_ALLOW	=1406;	/* NetLabel: allow unlabeled traffic */
static const int AUDIT_MAC_CIPSOV4_ADD	=1407;	/* NetLabel: add CIPSOv4 DOI entry */
static const int AUDIT_MAC_CIPSOV4_DEL	=1408;	/* NetLabel: del CIPSOv4 DOI entry */
static const int AUDIT_MAC_MAP_ADD	=1409;	/* NetLabel: add LSM domain mapping */
static const int AUDIT_MAC_MAP_DEL	=1410;	/* NetLabel: del LSM domain mapping */
static const int AUDIT_MAC_IPSEC_ADDSA	=1411;	/* Not used */
static const int AUDIT_MAC_IPSEC_DELSA	=1412;	/* Not used  */
static const int AUDIT_MAC_IPSEC_ADDSPD	=1413;	/* Not used */
static const int AUDIT_MAC_IPSEC_DELSPD	=1414;	/* Not used */
static const int AUDIT_MAC_IPSEC_EVENT	=1415;	/* Audit an IPSec event */
static const int AUDIT_MAC_UNLBL_STCADD	=1416;	/* NetLabel: add a static label */
static const int AUDIT_MAC_UNLBL_STCDEL	=1417;	/* NetLabel: del a static label */
]]

ffi.cdef[[
static const int AUDIT_FIRST_KERN_ANOM_MSG   =1700;
static const int AUDIT_LAST_KERN_ANOM_MSG    =1799;
static const int AUDIT_ANOM_PROMISCUOUS      =1700; /* Device changed promiscuous mode */
static const int AUDIT_ANOM_ABEND            =1701; /* Process ended abnormally */
static const int AUDIT_ANOM_LINK		    =1702; /* Suspicious use of file links */
static const int AUDIT_INTEGRITY_DATA	    =1800; /* Data integrity verification */
static const int AUDIT_INTEGRITY_METADATA    =1801; /* Metadata integrity verification */
static const int AUDIT_INTEGRITY_STATUS	    =1802; /* Integrity enable status */
static const int AUDIT_INTEGRITY_HASH	    =1803; /* Integrity HASH type */
static const int AUDIT_INTEGRITY_PCR	    =1804; /* PCR invalidation msgs */
static const int AUDIT_INTEGRITY_RULE	    =1805; /* policy rule */
]]

ffi.cdef[[
static const int AUDIT_KERNEL		=2000;	/* Asynchronous audit record. NOT A REQUEST. */
]]

ffi.cdef[[
/* Rule flags */
static const int AUDIT_FILTER_USER	=0x00;	/* Apply rule to user-generated messages */
static const int AUDIT_FILTER_TASK	=0x01;	/* Apply rule at task creation (not syscall) */
static const int AUDIT_FILTER_ENTRY	=0x02;	/* Apply rule at syscall entry */
static const int AUDIT_FILTER_WATCH	=0x03;	/* Apply rule to file system watches */
static const int AUDIT_FILTER_EXIT	=0x04;	/* Apply rule at syscall exit */
static const int AUDIT_FILTER_TYPE	=0x05;	/* Apply rule at audit_log_start */

static const int AUDIT_NR_FILTERS	=6;

static const int AUDIT_FILTER_PREPEND	=0x10;	/* Prepend to front of list */
]]

ffi.cdef[[
/* Rule actions */
static const int AUDIT_NEVER    =0;	/* Do not build context if rule matches */
static const int AUDIT_POSSIBLE =1;	/* Build context if rule matches  */
static const int AUDIT_ALWAYS   =2;	/* Generate audit record if rule matches */

/* Rule structure sizes -- if these change, different AUDIT_ADD and
 * AUDIT_LIST commands must be implemented. */
static const int AUDIT_MAX_FIELDS   =64;
static const int AUDIT_MAX_KEY_LEN  =256;
static const int AUDIT_BITMASK_SIZE =64;
]]


--[[
local function AUDIT_WORD(nr) ((uint32_t)((nr)/32))
local function AUDIT_BIT(nr)  (1 << ((nr) - AUDIT_WORD(nr)*32))
--]]

ffi.cdef[[
static const int AUDIT_SYSCALL_CLASSES =16;
static const int AUDIT_CLASS_DIR_WRITE =0;
static const int AUDIT_CLASS_DIR_WRITE_32 =1;
static const int AUDIT_CLASS_CHATTR =2;
static const int AUDIT_CLASS_CHATTR_32 =3;
static const int AUDIT_CLASS_READ =4;
static const int AUDIT_CLASS_READ_32 =5;
static const int AUDIT_CLASS_WRITE =6;
static const int AUDIT_CLASS_WRITE_32 =7;
static const int AUDIT_CLASS_SIGNAL =8;
static const int AUDIT_CLASS_SIGNAL_32 =9;

/* This bitmask is used to validate user input.  It represents all bits that
 * are currently used in an audit field constant understood by the kernel.
 * If you are adding a new static const int AUDIT_<whatever>, please ensure that
 * AUDIT_UNUSED_BITS is updated if need be. */
static const int AUDIT_UNUSED_BITS	=0x07FFFC00;

/* AUDIT_FIELD_COMPARE rule list */
static const int AUDIT_COMPARE_UID_TO_OBJ_UID	=1;
static const int AUDIT_COMPARE_GID_TO_OBJ_GID	=2;
static const int AUDIT_COMPARE_EUID_TO_OBJ_UID	=3;
static const int AUDIT_COMPARE_EGID_TO_OBJ_GID	=4;
static const int AUDIT_COMPARE_AUID_TO_OBJ_UID	=5;
static const int AUDIT_COMPARE_SUID_TO_OBJ_UID	=6;
static const int AUDIT_COMPARE_SGID_TO_OBJ_GID	=7;
static const int AUDIT_COMPARE_FSUID_TO_OBJ_UID	=8;
static const int AUDIT_COMPARE_FSGID_TO_OBJ_GID	=9;

static const int AUDIT_COMPARE_UID_TO_AUID	=10;
static const int AUDIT_COMPARE_UID_TO_EUID	=11;
static const int AUDIT_COMPARE_UID_TO_FSUID	=12;
static const int AUDIT_COMPARE_UID_TO_SUID	=13;

static const int AUDIT_COMPARE_AUID_TO_FSUID	=14;
static const int AUDIT_COMPARE_AUID_TO_SUID	=15;
static const int AUDIT_COMPARE_AUID_TO_EUID	=16;

static const int AUDIT_COMPARE_EUID_TO_SUID	=17;
static const int AUDIT_COMPARE_EUID_TO_FSUID	=18;

static const int AUDIT_COMPARE_SUID_TO_FSUID	=19;

static const int AUDIT_COMPARE_GID_TO_EGID	=20;
static const int AUDIT_COMPARE_GID_TO_FSGID	=21;
static const int AUDIT_COMPARE_GID_TO_SGID	=22;

static const int AUDIT_COMPARE_EGID_TO_FSGID	=23;
static const int AUDIT_COMPARE_EGID_TO_SGID	=24;
static const int AUDIT_COMPARE_SGID_TO_FSGID	=25;

static const int AUDIT_MAX_FIELD_COMPARE		=AUDIT_COMPARE_SGID_TO_FSGID;
]]

ffi.cdef[[
/* Rule fields */
				/* These are useful when checking the
				 * task structure at task creation time
				 * (AUDIT_PER_TASK).  */
static const int AUDIT_PID	=0;
static const int AUDIT_UID	=1;
static const int AUDIT_EUID	=2;
static const int AUDIT_SUID	=3;
static const int AUDIT_FSUID	=4;
static const int AUDIT_GID	=5;
static const int AUDIT_EGID	=6;
static const int AUDIT_SGID	=7;
static const int AUDIT_FSGID	=8;
static const int AUDIT_LOGINUID	=9;
static const int AUDIT_PERS	=10;
static const int AUDIT_ARCH	=11;
static const int AUDIT_MSGTYPE	=12;
static const int AUDIT_SUBJ_USER	=13;	/* security label user */
static const int AUDIT_SUBJ_ROLE	=14;	/* security label role */
static const int AUDIT_SUBJ_TYPE	=15;	/* security label type */
static const int AUDIT_SUBJ_SEN	=16;	/* security label sensitivity label */
static const int AUDIT_SUBJ_CLR	=17;	/* security label clearance label */
static const int AUDIT_PPID	=18;
static const int AUDIT_OBJ_USER	=19;
static const int AUDIT_OBJ_ROLE	=20;
static const int AUDIT_OBJ_TYPE	=21;
static const int AUDIT_OBJ_LEV_LOW	=22;
static const int AUDIT_OBJ_LEV_HIGH	=23;
static const int AUDIT_LOGINUID_SET	=24;
]]

ffi.cdef[[
				/* These are ONLY useful when checking
				 * at syscall exit time (AUDIT_AT_EXIT). */
static const int AUDIT_DEVMAJOR	=100;
static const int AUDIT_DEVMINOR	=101;
static const int AUDIT_INODE	=102;
static const int AUDIT_EXIT	=103;
static const int AUDIT_SUCCESS   =104;	/* exit >= 0; value ignored */
static const int AUDIT_WATCH	=105;
static const int AUDIT_PERM	=106;
static const int AUDIT_DIR	=107;
static const int AUDIT_FILETYPE	=108;
static const int AUDIT_OBJ_UID	=109;
static const int AUDIT_OBJ_GID	=110;
static const int AUDIT_FIELD_COMPARE	=111;

static const int AUDIT_ARG0      =200;
static const int AUDIT_ARG1      =(AUDIT_ARG0+1);
static const int AUDIT_ARG2      =(AUDIT_ARG0+2);
static const int AUDIT_ARG3      =(AUDIT_ARG0+3);

static const int AUDIT_FILTERKEY	=210;

static const int AUDIT_NEGATE			=0x80000000;

/* These are the supported operators.
 *	4  2  1  8
 *	=  >  <  ?
 *	----------
 *	0  0  0	 0	00	nonsense
 *	0  0  0	 1	08	&  bit mask
 *	0  0  1	 0	10	<
 *	0  1  0	 0	20	>
 *	0  1  1	 0	30	!=
 *	1  0  0	 0	40	=
 *	1  0  0	 1	48	&=  bit test
 *	1  0  1	 0	50	<=
 *	1  1  0	 0	60	>=
 *	1  1  1	 1	78	all operators
 */
static const int AUDIT_BIT_MASK			=0x08000000;
static const int AUDIT_LESS_THAN			=0x10000000;
static const int AUDIT_GREATER_THAN		=0x20000000;
static const int AUDIT_NOT_EQUAL		=	0x30000000;
static const int AUDIT_EQUAL			=0x40000000;
static const int AUDIT_BIT_TEST			=(AUDIT_BIT_MASK|AUDIT_EQUAL);
static const int AUDIT_LESS_THAN_OR_EQUAL	=(AUDIT_LESS_THAN|AUDIT_EQUAL);
static const int AUDIT_GREATER_THAN_OR_EQUAL	=(AUDIT_GREATER_THAN|AUDIT_EQUAL);
static const int AUDIT_OPERATORS			=(AUDIT_EQUAL|AUDIT_NOT_EQUAL|AUDIT_BIT_MASK);
]]


ffi.cdef[[
enum {
	Audit_equal,
	Audit_not_equal,
	Audit_bitmask,
	Audit_bittest,
	Audit_lt,
	Audit_gt,
	Audit_le,
	Audit_ge,
	Audit_bad
};
]]

--[[
/* Status symbols */
				/* Mask values */
static const int AUDIT_STATUS_ENABLED		0x0001
static const int AUDIT_STATUS_FAILURE		0x0002
static const int AUDIT_STATUS_PID		0x0004
static const int AUDIT_STATUS_RATE_LIMIT		0x0008
static const int AUDIT_STATUS_BACKLOG_LIMIT	0x0010
static const int AUDIT_STATUS_BACKLOG_WAIT_TIME	0x0020

static const int AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT	0x00000001
static const int AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME	0x00000002
static const int AUDIT_FEATURE_BITMAP_ALL (AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT | \
				  AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME)

/* deprecated: AUDIT_VERSION_* */
static const int AUDIT_VERSION_LATEST 		AUDIT_FEATURE_BITMAP_ALL
static const int AUDIT_VERSION_BACKLOG_LIMIT	AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT
static const int AUDIT_VERSION_BACKLOG_WAIT_TIME	AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME

				/* Failure-to-log actions */
static const int AUDIT_FAIL_SILENT	0
static const int AUDIT_FAIL_PRINTK	1
static const int AUDIT_FAIL_PANIC	2
--]]

ffi.cdef[[
/*
 * These bits disambiguate different calling conventions that share an
 * ELF machine type, bitness, and endianness
 */
static const int __AUDIT_ARCH_CONVENTION_MASK 		= 0x30000000;
static const int __AUDIT_ARCH_CONVENTION_MIPS64_N32 = 0x20000000;
]]

ffi.cdef[[
/* distinguish syscall tables */
static const int __AUDIT_ARCH_64BIT = 0x80000000;
static const int __AUDIT_ARCH_LE	= 0x40000000;
]]

ffi.cdef[[
static const int AUDIT_ARCH_AARCH64	=(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_ALPHA	=(EM_ALPHA|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_ARM		=(EM_ARM|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_ARMEB	=(EM_ARM);
static const int AUDIT_ARCH_CRIS	=	(EM_CRIS|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_FRV		=(EM_FRV);
static const int AUDIT_ARCH_I386		=(EM_386|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_IA64		=(EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_M32R		=(EM_M32R);
static const int AUDIT_ARCH_M68K		=(EM_68K);
//static const int AUDIT_ARCH_MICROBLAZE	=(EM_MICROBLAZE);
static const int AUDIT_ARCH_MIPS		=(EM_MIPS);
static const int AUDIT_ARCH_MIPSEL	=(EM_MIPS|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_MIPS64	=(EM_MIPS|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_MIPS64N32	=(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_CONVENTION_MIPS64_N32);
static const int AUDIT_ARCH_MIPSEL64	=(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_MIPSEL64N32	=(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE|__AUDIT_ARCH_CONVENTION_MIPS64_N32);
static const int AUDIT_ARCH_OPENRISC	=(EM_OPENRISC);
static const int AUDIT_ARCH_PARISC	=(EM_PARISC);
static const int AUDIT_ARCH_PARISC64	=(EM_PARISC|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_PPC		=(EM_PPC);
/* do not define AUDIT_ARCH_PPCLE since it is not supported by audit */
static const int AUDIT_ARCH_PPC64	=(EM_PPC64|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_PPC64LE	=(EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_S390	=	(EM_S390);
static const int AUDIT_ARCH_S390X	=(EM_S390|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_SH		=(EM_SH);
static const int AUDIT_ARCH_SHEL	=	(EM_SH|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_SH64	=	(EM_SH|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_SHEL64	=(EM_SH|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
static const int AUDIT_ARCH_SPARC	=(EM_SPARC);
static const int AUDIT_ARCH_SPARC64	=(EM_SPARCV9|__AUDIT_ARCH_64BIT);
static const int AUDIT_ARCH_X86_64	=(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE);
]]

ffi.cdef[[
static const int AUDIT_PERM_EXEC	= 1;
static const int AUDIT_PERM_WRITE	= 2;
static const int AUDIT_PERM_READ	= 4;
static const int AUDIT_PERM_ATTR	= 8;
]]

ffi.cdef[[
/* MAX_AUDIT_MESSAGE_LENGTH is set in audit:lib/libaudit.h as:
 * 8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
 * max header+body+tailer: 44 + 29 + 32 + 262 + 7 + pad
 */
static const int AUDIT_MESSAGE_TEXT_MAX	= 8560;

/* Multicast Netlink socket groups (default up to 32) */
enum audit_nlgrps {
	AUDIT_NLGRP_NONE,	/* Group 0 not used */
	AUDIT_NLGRP_READLOG,	/* "best effort" read only socket */
	__AUDIT_NLGRP_MAX
};
static const int AUDIT_NLGRP_MAX               = (__AUDIT_NLGRP_MAX - 1);
]]

ffi.cdef[[
struct audit_status {
	uint32_t		mask;		/* Bit mask for valid entries */
	uint32_t		enabled;	/* 1 = enabled, 0 = disabled */
	uint32_t		failure;	/* Failure-to-log action */
	uint32_t		pid;		/* pid of auditd process */
	uint32_t		rate_limit;	/* messages rate limit (per second) */
	uint32_t		backlog_limit;	/* waiting messages limit */
	uint32_t		lost;		/* messages lost */
	uint32_t		backlog;	/* messages waiting in queue */
	union {
		uint32_t	version;	/* deprecated: audit api version num */
		uint32_t	feature_bitmap;	/* bitmap of kernel audit features */
	};
	uint32_t		backlog_wait_time;/* message queue wait timeout */
};

struct audit_features {
	uint32_t	vers;
	uint32_t	mask;		/* which bits we are dealing with */
	uint32_t	features;	/* which feature to enable/disable */
	uint32_t	lock;		/* which features to lock */
};
]]

ffi.cdef[[
static const int AUDIT_FEATURE_VERSION	=1;

static const int AUDIT_FEATURE_ONLY_UNSET_LOGINUID	=0;
static const int AUDIT_FEATURE_LOGINUID_IMMUTABLE	=1;
static const int AUDIT_LAST_FEATURE			=AUDIT_FEATURE_LOGINUID_IMMUTABLE;
]]

--local function audit_feature_valid(x)		((x) >= 0 && (x) <= AUDIT_LAST_FEATURE)
--local function AUDIT_FEATURE_TO_MASK(x)	(1 << ((x) & 31)) /* mask for uint32_t */

ffi.cdef[[
struct audit_tty_status {
	uint32_t		enabled;	/* 1 = enabled, 0 = disabled */
	uint32_t		log_passwd;	/* 1 = enabled, 0 = disabled */
};

static const int AUDIT_UID_UNSET = (unsigned int)-1;

]]


ffi.cdef[[
/* audit_rule_data supports filter rules with both integer and string
 * fields.  It corresponds with AUDIT_ADD_RULE, AUDIT_DEL_RULE and
 * AUDIT_LIST_RULES requests.
 */
struct audit_rule_data {
	uint32_t		flags;	/* AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND */
	uint32_t		action;	/* AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS */
	uint32_t		field_count;
	uint32_t		mask[AUDIT_BITMASK_SIZE]; /* syscall(s) affected */
	uint32_t		fields[AUDIT_MAX_FIELDS];
	uint32_t		values[AUDIT_MAX_FIELDS];
	uint32_t		fieldflags[AUDIT_MAX_FIELDS];
	uint32_t		buflen;	/* total length of string fields */
	char		buf[0];	/* string fields buffer */
};
]]
