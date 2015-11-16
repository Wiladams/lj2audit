local ffi = require("ffi")

ffi.cdef[[
/* These constants define the various ELF target machines */
static const int EM_NONE	=0;
static const int EM_M32		=1;
static const int EM_SPARC	=2;
static const int EM_386		=3;
static const int EM_68K		=4;
static const int EM_88K		=5;
static const int EM_486		=6;	/* Perhaps disused */
static const int EM_860		=7;
static const int EM_MIPS	=8;	/* MIPS R3000 (officially, big-endian only) */
				/* Next two are historical and binaries and
				   modules of these types will be rejected by
				   Linux.  */
static const int EM_MIPS_RS3_LE	=10;	/* MIPS R3000 little-endian */
static const int EM_MIPS_RS4_BE	=10;	/* MIPS R4000 big-endian */

static const int EM_PARISC	=15;	/* HPPA */
static const int EM_SPARC32PLUS	=18;	/* Sun's "v8plus" */
static const int EM_PPC		=20;	/* PowerPC */
static const int EM_PPC64	=21;	 /* PowerPC64 */
static const int EM_SPU		=23;	/* Cell BE SPU */
static const int EM_ARM		=40;	/* ARM 32 bit */
static const int EM_SH		=42;	/* SuperH */
static const int EM_SPARCV9	=43;	/* SPARC v9 64-bit */
static const int EM_IA_64	=50;	/* HP/Intel IA-64 */
static const int EM_X86_64	=62;	/* AMD x86-64 */
static const int EM_S390	=	22;	/* IBM S/390 */
static const int EM_CRIS	=	76;	/* Axis Communications 32-bit embedded processor */
static const int EM_V850	=	87;	/* NEC v850 */
static const int EM_M32R	=	88;	/* Renesas M32R */
static const int EM_MN10300	=89;	/* Panasonic/MEI MN10300, AM33 */
static const int EM_OPENRISC =    92;     /* OpenRISC 32-bit embedded processor */
static const int EM_BLACKFIN =    106;     /* ADI Blackfin Processor */
static const int EM_ALTERA_NIOS2	=113;	/* Altera Nios II soft-core processor */
static const int EM_TI_C6000	=140;	/* TI C6X DSPs */
static const int EM_AARCH64	=183;	/* ARM 64 bit */
static const int EM_FRV		=0x5441;	/* Fujitsu FR-V */
static const int EM_AVR32	=0x18ad;	/* Atmel AVR32 */

/*
 * This is an interim value that we will use until the committee comes
 * up with a final number.
 */
static const int EM_ALPHA	=0x9026;

/* Bogus old v850 magic number, used by old tools. */
static const int EM_CYGNUS_V850	=0x9080;
/* Bogus old m32r magic number, used by old tools. */
static const int EM_CYGNUS_M32R	=0x9041;
/* This is the old interim value for S/390 architecture */
static const int EM_S390_OLD	=0xA390;
/* Also Panasonic/MEI MN10300, AM33 */
static const int EM_CYGNUS_MN10300 =0xbeef;
]]

