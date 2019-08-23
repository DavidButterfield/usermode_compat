/* UMC_sys.h -- Usermode compatibility: basic definitions for kernel code
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser General
 * Public License, version 2.1 or any later version (LGPLv2.1 or later), or
 * the Apache License 2.0.
 *
 * This file is not intended to be included from code that was written to run
 * in usermode.
 *
 * We emulate functions to support code from a Linux kernel version the range
 * [2.6.24, 2.6.32].  More recent kernel code may be portable here if it has
 * its own "backport" wrappers to let it run on kernel 2.6.32 or 2.6.24.
 *
 * UMC can be thought of as a backport wrapper that augments an existing 2.6.32
 * backport, extending it further back all the way to usermode library calls.
 *
 * This file is automatically included from all the "application code" (kernel
 * code ported to run in usermode) source files.  Some header files are
 * #included from /usr/include and others from the reference kernel.  Some care
 * is required to avoid conflicts.
 *
 * Suggested editor window width >= 96.
 */
#ifndef UMC_SYS_H
#define UMC_SYS_H
#define _GNU_SOURCE

#define TRACE_syscall_err		defined

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE		KERNEL_VERSION(2, 6, 32)
#endif

#define BITS_PER_BYTE			8
#define BYTES_PER_LONG			8 //XXX (sizeof(long))
#define BITS_PER_LONG			(BITS_PER_BYTE * BYTES_PER_LONG)

#define _ASM_GENERIC_BITOPS_HWEIGHT_H_	/* inhibit hweight.h */
#define __struct_tm_defined		/* inhibit struct_tm.h */
#define ffs UMC_unused_ffs		/* inhibit defining function ffs in string.h */

/* These headers come from /usr/include */
#include <features.h>	// otherwise _GNU_SOURCE fails to work
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>	// random()

#include </usr/include/x86_64-linux-gnu/bits/types/struct_iovec.h>  //XXX

#include <string.h>
#undef ffs

#ifndef gettid
#define gettid()			((pid_t)(syscall(SYS_gettid)))
#endif

#ifndef tkill
#define tkill(tid, sig)			(int)(syscall(__NR_tkill, tid, sig))
#endif

/********** Compiler tricks **********/

/* Make a string out of a token */
#define __stringify(TOKEN)		__STRINGIFY(TOKEN)
#define __STRINGIFY(TOKEN)		#TOKEN

/* Concatinate two tokens into a single token */
#define _CONCAT(a, b)                   __CONCAT__(a, b)
#define __CONCAT__(a, b)                a##b

/* Identify a line of source code */
#define FL_STR				__FILE__":"__stringify(__LINE__)

/* Avoid "unused" warnings in stubbed-out macros */
#define _USE(x)				({ if (0 && (uintptr_t)(x)==0) {}; 0; })

/* Remove the "const" qualifier from a pointer */
static inline void *
_unconstify(const void * cvp)
{
    union { void * vp; void const * cvp; } p;
    p.cvp = cvp;
    return p.vp;
}

/* Compiler hints */
#define __pure				__attribute__((__pure__))
#define __noreturn			__attribute__((__noreturn__))
#define __must_check			__attribute__((__warn_unused_result__))
#define __aligned(align)		__attribute__((__aligned__(align)))
#define __packed			__attribute__((__packed__))
#define __printf(F, A)			__attribute__((__format__(printf,F,A)))
#define __maybe_unused			__attribute__((__unused__))

/* Compiler branch hints */
#define PREDICT(e, p)                   __builtin_expect((long)(e), (long)(p))
#define likely(e)                       PREDICT((e) != 0, true)
#define unlikely(e)                     PREDICT((e) != 0, false)

/* Encode a -errno into a pointer */
#define PTR_ERR(ptr)			((intptr_t)(ptr))
#define ERR_PTR(err)			((void *)(intptr_t)(err))
#define IS_ERR(ptr)			unlikely((unsigned long)(void *)(ptr) \
							> (unsigned long)(-4096))
#define IS_ERR_OR_NULL(ptr)		(unlikely(!ptr) || IS_ERR(ptr))

/********** Types and math **********/

typedef unsigned short			umode_t;
typedef unsigned int			fmode_t;

#define FMODE_READ			0x01
#define FMODE_WRITE			0x02
#define FMODE_NDELAY			0x40
#define FMODE_EXCL			0x80

#define hash_long(val, ORDER)		(     (long)(val) % ( 1ul << (ORDER) ) )
#define hash_32(val, ORDER)		( (uint32_t)(val) % ( 1ul << (ORDER) ) )

#define div_u64(num, den)		((num) / (den))

#define	hweight8(v8)			__builtin_popcount(v8)
#define	hweight16(v16)			__builtin_popcount(v16)
#define	hweight32(v32)			__builtin_popcount(v32)
#define	hweight64(v64)			__builtin_popcountl((unsigned long)(v64))

#define __CACHE_LINE_BYTES		64  /* close enough */
#define SMP_CACHE_BYTES			__CACHE_LINE_BYTES
#define ____cacheline_aligned		__attribute__((aligned(__CACHE_LINE_BYTES)))
#define ____cacheline_aligned_in_smp	__attribute__((aligned(SMP_CACHE_BYTES)))

/******************************************************************************/

//XXXX ADD sys_buf_cache_size() to the sys_services API
//XXX This bogus hack reply works for the one place it gets called from
#define sys_buf_cache_size(cache) ({ \
    expect_eq(strcmp(__func__, "lc_create"), 0, \
		"XXX XXX XXX check sys_buf_cache_size() macro usage in %s", __func__); \
    ((unsigned)(-1));   /*XXX "as big as you need" */ \
})

/******************************************************************************/
#include <sys_service.h>    /* system services: event threads, polling, memory, time, etc */
extern void sys_breakpoint(void);

#include <byteswap.h>
#include <endian.h>

/* Some headers in /usr/include depend on the usermode endian conventions,
 * while some kernel header files depend on the kernel endian conventions.
 * Now that we have done the includes from /usr/include, we'll fixup the
 * endian indicators, before including header files from the reference kernel.
 */
#if !defined(__BIG_ENDIAN) || !defined(__LITTLE_ENDIAN) || !defined(__BYTE_ORDER)
  #error Usermode is expected to begin with both __BIG_ENDIAN and __LITTLE_ENDIAN #defined
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
  #undef __LITTLE_ENDIAN    /* Adjustment for usage by code written for kernel */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  #undef __BIG_ENDIAN	    /* Adjustment for usage by code written for kernel */
#else
  #error Unknown ENDIAN
#endif

#ifndef __KERNEL__
#define __KERNEL__  /* what we are compiling thinks it is kernel code */
#endif

#define MODULE

#define COMPILE_OFFSETS			/* inhibit asm/asm-offsets.h */

/* Influence how various kernel code gets compiled -- most of these probably
 * don't do much here in usermode */

#define CONFIG_ENABLE_MUST_CHECK
#define CONFIG_ENABLE_WARN_DEPRECATED

#define CONFIG_X86_64
#define CONFIG_64BIT
#define CONFIG_SMP
#define CONFIG_LBDAF
#define CONFIG_PHYS_ADDR_T_64BIT

#define CONFIG_X86_BSWAP
#define CONFIG_X86_CMOV

//NEVER #define CONFIG_GENERIC_FIND_FIRST_BIT
//NEVER #define CONFIG_GENERIC_FIND_NEXT_BIT
//NEVER #define CONFIG_GENERIC_FIND_LAST_BIT

#define CONFIG_HZ_1000
#define CONFIG_HZ 1000

#define CONFIG_NR_CPUS 64

#define CONFIG_BUG
#define CONFIG_PROC_FS

#define CONFIG_NET

// #define CONFIG_GENERIC_BUG			    //XXX untried
// #define CONFIG_GENERIC_BUG_RELATIVE_POINTERS	    //XXX untried

// #define CONFIG_DEBUG_LIST			    //XXX untried
// #define CONFIG_DEBUG_SG			    //XXX untried
// #define CONFIG_DEBUG_BUGVERBOSE		    //XXX untried

#define __used				/* */
#define __visible			/* */
#define __init				/* */
#define __exit				/* */
#define __force				/* */
#define __user				/* */
#define __iomem				/* */
#define __read_mostly			/* */
#define __cold				/* */

#define uninitialized_var(x)		x = x

#define barrier()			__sync_synchronize()

/* Qualify a pointer so that its target is treated as volatile */
#define _VOLATIZE(ptr)			((volatile const typeof(ptr))(ptr))
#define WRITE_ONCE(x, val)		(*_VOLATIZE(&(x)) = (val))
#define READ_ONCE(x)			(*_VOLATIZE(&(x)))
#define	ACCESS_ONCE(x)			READ_ONCE(x)

/* For stubbing out unused functions, macro arguments, etc */
#define IGNORED				0
#define DO_NOTHING(USED...)		do { USED; } while (0)
extern __thread size_t UMC_size_t_JUNK; /* avoid unused-value gcc warnings */

/* For stubbing out functions that if someone calls them we want to know */
#define UMC_STUB_STR			"XXX XXX XXX XXX XXX UNIMPLEMENTED "
#define UMC_STUB(fn, ret...)		({ WARN_ONCE(true, UMC_STUB_STR "FUNCTION %s\n", #fn); \
					  (UMC_size_t_JUNK=(uintptr_t)IGNORED), ##ret;})

/* Translate an rc/errno system-call return into a kernel-style -errno return */
#define _UMC_kernelize(callret...) \
    ({ int k_rc = (callret); unlikely(k_rc < 0) ? -errno : k_rc; })

#define _UMC_kernelize64(callret...) \
    ({ ssize_t k_rc = (callret); unlikely(k_rc < 0) ? -errno : k_rc; })

#ifndef TRACE_syscall_err

#define UMC_kernelize(callret...)	_UMC_kernelize(callret)
#define UMC_kernelize64(callret...)	_UMC_kernelize64(callret)

#else	/* version that warns on errors */

#define UMC_kernelize(callret...) \
({ \
    int uk_ret = _UMC_kernelize(callret); \
    if (uk_ret < 0 && uk_ret != -EAGAIN) \
	pr_warning("%s returned %d\n", #callret, uk_ret); \
    uk_ret; \
})

#define UMC_kernelize64(callret...) \
({ ssize_t uk64_ret = _UMC_kernelize64(callret); \
    if (uk64_ret < 0 && uk64_ret != -EAGAIN) \
	pr_warning("%s returned %d\n", #callret, uk64_ret); \
    uk64_ret; \
})

#endif	/* TRACE_syscall_err */

#define HZ				CONFIG_HZ

#define kvec				iovec
#define UIO_FASTIOV			8
#define UIO_MAXIOV			1024

#define	ERESTARTSYS			512
#define ENOTSUPP			ENOTSUP

#define capable(cap)			(geteuid() == 0)    //XXX
#define CAP_SYS_ADMIN			21

#define KERN_LOC_FIELDS			current->pid, __func__, __LINE__, __FILE__
#define KERN_LOC_FMT			"[%u] %s:%u (%s):"

struct sysinfo;
extern void si_meminfo(struct sysinfo *si);

static inline unsigned long
_find_next_bit(const unsigned long *src, unsigned long nbits,
				    unsigned long startbit, bool wanted)
{
    unsigned long bitno = startbit;
    unsigned long idx;
    unsigned long bitmask;
    while (bitno < nbits) {
	idx = bitno / BITS_PER_LONG;
	bitmask = 1UL << (bitno % BITS_PER_LONG);
	if (!!(src[idx] & bitmask) == wanted)
	    return bitno;
	bitno++;
    }
    return nbits;
}

#define find_next_bit(src, nbits, startbit)	    _find_next_bit(src, nbits, startbit, true)
#define find_next_zero_bit(src, nbits, startbit)    _find_next_bit(src, nbits, startbit, false)
#define	find_first_bit(src, nbits)		    find_next_bit(src, nbits, 0)
#define	find_first_zero_bit(src, nbits)		    find_next_zero_bit(src, nbits, 0)

#define _LINUX_UNALIGNED_ACCESS_OK_H		    /* inhibit access_ok.h */

/* Override the __WARN() in bug.h included from linux/kernel.h */
#define __WARN()    printk(KERN_WARNING "at %s\n", FL_STR);

#include <linux/kernel.h>   /* linux/kernel.h is the first kernel header file to #include */

//XXXX Should use unlocked_stdio in place of fprintf() if aborting

/* Override declarations of these in linux/kernel.h */
#define vprintk(fmt, va_list)	vfprintf(stderr, fmt, va_list)
//#define printk(fmt, args...)	fprintf(stderr, "[%d]" FL_STR "> " fmt, gettid(), ##args)
#define printk(fmt, args...)	fprintf(stderr, fmt, ##args)

#define nlprintk(fmtargs...)	_nlprintk(""fmtargs)
#define _nlprintk(fmt, args...)	printk(FL_STR ">" fmt"\n", ##args)

#define printk_ratelimit(void)				0
#define printk_timed_ratelimit(jiffies, interval_msec)	false

#include "UMC_kernel.h"	    /* include first after linux/kernel.h */

#include <linux/list.h>	    /* used all over the place */

/*** Unaligned access ***/
#define _DIRTY	__attribute__((__no_sanitize_undefined__))
static inline _DIRTY uint16_t get_unaligned_be16(void const * p) { return __builtin_bswap16(*(uint16_t const *)p); }
static inline _DIRTY uint32_t get_unaligned_be32(void const * p) { return __builtin_bswap32(*(uint32_t const *)p); }
static inline _DIRTY uint64_t get_unaligned_be64(void const * p) { return __builtin_bswap64(*(uint64_t const *)p); }
static inline _DIRTY uint16_t get_unaligned_le16(void const * p) { return                  (*(uint16_t const *)p); }
static inline _DIRTY uint32_t get_unaligned_le32(void const * p) { return                  (*(uint32_t const *)p); }
static inline _DIRTY uint64_t get_unaligned_le64(void const * p) { return                  (*(uint64_t const *)p); }
static inline _DIRTY void put_unaligned_be16(uint16_t v, void * p) { *(uint16_t *)p = __builtin_bswap16(v); }
static inline _DIRTY void put_unaligned_be32(uint32_t v, void * p) { *(uint32_t *)p = __builtin_bswap32(v); }
static inline _DIRTY void put_unaligned_be64(uint64_t v, void * p) { *(uint64_t *)p = __builtin_bswap64(v); }
static inline _DIRTY void put_unaligned_le16(uint16_t v, void * p) { *(uint16_t *)p =                  (v); }
static inline _DIRTY void put_unaligned_le32(uint32_t v, void * p) { *(uint32_t *)p =                  (v); }
static inline _DIRTY void put_unaligned_le64(uint64_t v, void * p) { *(uint64_t *)p =                  (v); }

static inline bool
_bitmap_test_bit(const unsigned long * src, unsigned int bitno)
{
    unsigned int idx = bitno / BITS_PER_LONG;
    unsigned long bitmask = 1UL << (bitno % BITS_PER_LONG);
    return (src[idx] & bitmask) != 0;
}

static inline void
_bitmap_set_bit(unsigned long * dst, unsigned int bitno)
{
    unsigned int idx = bitno / BITS_PER_LONG;
    unsigned long bitmask = 1UL << (bitno % BITS_PER_LONG);
    dst[idx] |= bitmask;
}

#include <linux/bitmap.h>

#define set_bit(bitno, ptr)		test_and_set_bit((bitno), (ptr))
#define clear_bit(bitno, ptr)		test_and_clear_bit((bitno), (ptr))
#define change_bit(bitno, ptr)		test_and_change_bit((bitno), (ptr))
#define clear_bit_unlock(nr, addr)	clear_bit((nr), (addr))

#define scnprintf(buf, bufsize, fmtargs...) snprintf((buf), (bufsize), fmtargs)
#define vscnprintf(buf, bufsize, fmt, va)   vsnprintf((buf), (bufsize), fmt, va)

#define _kvasprintf(_retp, fmt, va)					    \
({									    \
    char * _str;							    \
    int _len = vasprintf(&_str, fmt, va);				    \
    if (_len < 0) {							    \
	*(_retp) = NULL;						    \
    } else {								    \
	*(_retp) = strncpy(vmalloc(1 + _len), _str, 1 + _len);	    \
	free(_str);							    \
    }									    \
    _len;								    \
})

#define kvasprintf(gfp, fmt, va) \
({ \
    char * _ret; \
    int const _rc = _kvasprintf(&_ret, fmt, va); \
    if (_rc < 0) \
	_ret = NULL; \
    _ret; \
})

/* Return a newly-allocated freeable formatted string from the printf-like arguments */
//XXX These should be non-inline varargs functions (instead of macros)

/* Use asprintf(), then copy result into our tracked memory */
#define _kasprintf(_retp, fmtargs...)					    \
({									    \
    char * _str;							    \
    int _len = asprintf(&_str, fmtargs);					    \
    if (_len < 0) {							    \
	*(_retp) = NULL;						    \
    } else {								    \
	*(_retp) = strncpy(vmalloc(1 + _len), _str, 1 + _len);	    \
	free(_str);							    \
    }									    \
    _len;								    \
})

#define kasprintf(gfp, fmt, args...) \
({ \
    char * _ret; \
    int const _rc = _kasprintf(&_ret, fmt, ##args); \
    if (_rc < 0) \
	_ret = NULL; \
    _ret; \
})

#define panic(fmtargs...) \
do { \
    pr_err(fmtargs); \
    dump_stack(); \
    sys_abort(); \
} while (0)

#define random32()  random()

static inline void
get_random_bytes(void * addr, int len)
{
    char * p = addr;
    int i;
    for (i = 0; i < len; i++)
	p[i] = (char)random();
}

extern char * UMC_string_concat_free(char * prefix, char * suffix);

extern char * strnchr(const char * str, size_t strmax, int match);

#define UMC_system(cmd) system(cmd)

/* Call (another) usermode program */
extern int call_usermodehelper(const char * progpath,
			       char * argv[], char * envp[], int waitflag);

#define UMH_NO_WAIT		0
#define UMH_WAIT_PROC		2	/* wait for the process to complete */

/******************************************************************************/
/* Create externally-visible entry points for module init/exit functions */

#define module_init(fn)	\
    extern error_t _CONCAT(UMC_INIT_, fn)(void); \
    error_t _CONCAT(UMC_INIT_, fn)(void) { return fn(); }

#define module_exit(fn)	\
    extern void _CONCAT(UMC_EXIT_, fn)(void); \
    void _CONCAT(UMC_EXIT_, fn)(void) { fn(); }

#define MODULE_VERSION(str) \
    static __attribute__((__unused__)) \
	char * MODULE_VERSION = ("MODULE_VERSION='"str"_LIB'" \
				"(adapted to usermode)")

#define MODULE_LICENSE(str) \
    static __attribute__((__unused__)) \
	char * MODULE_LICENSE = ("MODULE_LICENSE='"str"'")

#define MODULE_AUTHOR(str) \
    static __attribute__((__unused__)) \
	char * _CONCAT(MODULE_AUTHOR, __LINE__) = \
	    ("MODULE_AUTHOR='"str"'\nUsermode adaptations by DAB")

#define MODULE_DESCRIPTION(str) \
    static __attribute__((__unused__)) \
	char * MODULE_DESCRIPTION = ("MODULE_DESCRIPTION='"str"'")

#define MODULE_NAME_LEN			56
struct modversion_info { unsigned long crc; char name[MODULE_NAME_LEN]; };
struct module { char name[MODULE_NAME_LEN]; char * version; };

#ifndef THIS_MODULE
extern struct module UMC_module;
#define THIS_MODULE (&UMC_module)
#endif

#define module_param_string(h1, h2, size_h2, mode)  /* */
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major)	    /* */

#define MODULE_INFO(ver, str)		/* */
#define MODULE_PARM_DESC(var, desc)	/* */

#define get_module_info(arg)		(-EINVAL)
#define try_module_get(module)		true
#define request_module(a, b)		DO_NOTHING()
#define module_put(module)		DO_NOTHING()

struct kernel_param {			/* unused */
    unsigned int		      * arg;
};

#define EXPORT_SYMBOL(sym)		/* */
#define EXPORT_SYMBOL_GPL(sym)		/* */

#ifndef KBUILD_MODNAME
#define _MODNAME			""
#else
#define _MODNAME			KBUILD_MODNAME ": "
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern const char * UMC_fuse_mount_point;   /* path in real fs to fuse root */

/* These could be decoupled from UMC_sys.h, but seem convenient here */
#include "sys_assert.h"
#include "UMC_time.h"
#include "UMC_mem.h"

#endif /* UMC_SYS_H */
