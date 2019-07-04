/* usermode_lib.h
 * Shim for partial emulation/stubbing of selected Linux kernel functions in usermode
 * Copyright 2015 - 2019 David A. Butterfield
 *
 * This file is not intended to be #included from code that was written to run in usermode.
 *
 * Note that the functions here are implemented around the (apparent) semantics required by
 * particular kernel code of interest -- so they are not likely to conform to the full behavior
 * of the originals, which in many instances have not been consulted to validate these.  TODO
 */
#ifndef USERMODE_LIB_H
#define USERMODE_LIB_H
#define _GNU_SOURCE 1

/* This file is automatically included from all the "application code" (kernel code ported to
 * run in usermode) source files.  This file #includes some header files from /usr/include and
 * some header files from the reference kernel.  Some care is required to avoid conflicts.
 * Such header file conflicts can be very confusing, and slow to understand, because all your
 * usual assumptions about library interface consistency have to be checked.
 */

#ifndef __x86_64__
#warning usermode_lib shim has been compiled on 64-bit x86 only -- work required for other arch
#endif

/* Some headers in /usr/include depend on the usermode endian conventions, while some kernel
 * header files depend on the kernel endian conventions.  Below we will #include all the former
 * before fixing up the endian indicators, and #include all the latter after the fixup.
 */

#define _ASM_GENERIC_BITOPS_HWEIGHT_H_	    /* inhibit hweight.h */
#define __struct_tm_defined		    /* inhibit struct_tm.h */

/* These headers come from /usr/include */

#define ffs UMC_unused_ffs		    /* inhibit defining function ffs in string.h */
#include <string.h>
#undef ffs

#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>

/* From /usr/include sys/wait.h */
extern __pid_t waitpid (__pid_t __pid, int *__stat_loc, int __options);

/* From /usr/include sys/uio.h */
#define _SYS_UIO_H
struct iovec;
extern ssize_t readv (int __fd, const struct iovec *, int __count);
extern ssize_t writev (int __fd, const struct iovec *, int __count);
extern ssize_t preadv (int __fd, const struct iovec *, int __count, __off_t);
extern ssize_t pwritev (int __fd, const struct iovec *, int __count, __off_t);

/* This file (usermode_lib.h) contains the main shim implementation for emulation of
 * kernel services, using GNU C (usermode) library calls, definitions in the header
 * files above, and the system services defined in sys_service.h
 */
#include <sys_service.h>    /* system services: event threads, polling, memory, time, etc */
#include <sys_debug.h>	    /* assert, verify, expect, panic, warn, etc */

/* Fixup: avoid use of sys_service.h "expect" symbol conflicted by drbd */
#undef expect
#define expect_ne(x, y, fmtargs...)	_expect_ne((x), (y), ""fmtargs)
#define _expect_ne(x, y, fmt, args...)	expect_eq((x) == (y), 0, "%s == %s"fmt, \
						    __stringify(x), __stringify(y), ##args)

/* Fixup: kernel code doesn't follow the __BYTE_ORDER convention */
#include <byteswap.h>
#include <endian.h>

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
#define __KERNEL__			/* what we are compiling thinks it is kernel code */
#endif

#define MODULE

/* We emulate functions to support code from a Linux kernel version the range [2.6.24, 2.6.32].
 * More recent kernel code may be portable here if it has its own "backport" wrappers to let it
 * run on kernel 2.6.32 or 2.6.24.
 *
 * UMC can be thought of as a backport wrapper that augments an existing 2.6.32 backport,
 * extending it further back all the way to usermode library calls.
 */
#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE		KERNEL_VERSION(2, 6, 32)
#endif

/* Influence how various kernel code gets compiled */

#define COMPILE_OFFSETS			/* avoid asm/asm-offsets.h */

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

#define BITS_PER_BYTE			8
#define BYTES_PER_LONG			8 //XXX (sizeof(long))
#define BITS_PER_LONG			(BITS_PER_BYTE * BYTES_PER_LONG)

/* Compiler hints */
#define __pure				__attribute__((__pure__))
#define __noreturn			__attribute__((__noreturn__))
#define __must_check			__attribute__((__warn_unused_result__))
#define __aligned(align)		__attribute__((__aligned__(align)))
#define __packed			__attribute__((__packed__))
#define __printf(F, A)			__attribute__((__format__(printf,F,A)))

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

#define offsetof(TYPE, MEMBER)		__builtin_offsetof(TYPE, MEMBER)

#define	hweight8(v8)			__builtin_popcount(v8)
#define	hweight16(v16)			__builtin_popcount(v16)
#define	hweight32(v32)			__builtin_popcount(v32)
#define	hweight64(v64)			__builtin_popcountl(v64)

/* The kernel implementation requires HZ to be fixed at compile-time */
#define HZ				1000U

/* Qualify a pointer so that its target is treated as volatile */
#define _VOLATIZE(ptr)			((volatile const typeof(ptr))(ptr))
#define WRITE_ONCE(x, val)		(*_VOLATIZE(&(x)) = (val))
#define READ_ONCE(x)			(*_VOLATIZE(&(x)))
#define	ACCESS_ONCE(x)			READ_ONCE(x)


#define __WARN()			printk(KERN_WARNING "WARNING: at %s\n", FL_STR);
struct notifier_block;

#define barrier()			__sync_synchronize()

static inline unsigned long
_find_next_bit(const unsigned long *src, unsigned long nbits, unsigned long startbit, bool wanted)
{
    unsigned int bitno = startbit;
    unsigned int idx;
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

#include <linux/kernel.h>   /* linux/kernel.h is the first kernel header file to #include */

/* UMC_kernel.h should be included ahead of any kernel headers except linux/kernel.h */
#include "UMC_kernel.h"	    /* definitions from some kernel .h files we don't #include */

#include <sys/syscall.h>    /* ends up including a kernel header XXX */

#include <linux/list.h>

/********** Basic **********/

/* Symbol construction */
#define _CONCAT(a, b)                   __CONCAT__(a, b)
#define __CONCAT__(a, b)                a##b

#define _PER_THREAD			__thread

/* Remove the "const" qualifier from a pointer --
			    Places where this is needed should be fixed XXX */
static inline void *
_unconstify(void const * cvp)
{
    union { void * vp; void const * cvp; } p;
    p.cvp = cvp;
    return p.vp;
}

extern _PER_THREAD size_t UMC_size_t_JUNK;   /* avoid unused-value gcc warnings */

/* For stubbing out unused functions, macro arguments, etc */
#define IGNORED				0
#define DO_NOTHING(USED...)		do { USED; } while (0)

/* For stubbing out functions that if someone calls them we want to know */
#define UMC_STUB_STR			"XXX XXX XXX XXX XXX UNIMPLEMENTED"
#define UMC_STUB(fn, ret...)		({ WARN_ONCE(true, UMC_STUB_STR "FUNCTION %s\n", #fn); \
					  (UMC_size_t_JUNK=(uintptr_t)IGNORED), ##ret;})

/* Avoid compiler warnings for unused stubbed-out macro arguments */
#define _USE(x)				({ if (0 && (uintptr_t)(x)==0) {}; 0; })

#define kvec				iovec
#define UIO_FASTIOV			8
#define UIO_MAXIOV			1024

#define hash_long(val, ORDER)		(     (long)(val) % ( 1ul << (ORDER) ) )
#define hash_32(val, ORDER)		( (uint32_t)(val) % ( 1ul << (ORDER) ) )
#define div_u64(num, den)		((num) / (den))

static inline uint64_t
_ROUNDDOWN(uint64_t const v, uint64_t const q) { return v / q * q; }

static inline uint64_t
_ROUNDUP(uint64_t const v, uint64_t const q) { return (v + q - 1) / q * q; }

/* Translate an rc/errno system-call return into a kernel-style -errno return */
#define _UMC_kernelize(callret...) \
	    ({ int u_rc = (callret); unlikely(u_rc < 0) ? -errno : u_rc; })

#define _UMC_kernelize64(callret...) \
	    ({ ssize_t u_rc = (callret); unlikely(u_rc < 0) ? -errno : u_rc; })

// #define TRACE_syscall_err

#ifndef TRACE_syscall_err
#define UMC_kernelize(callret...)	_UMC_kernelize(callret)
#define UMC_kernelize64(callret...)	_UMC_kernelize64(callret)
#else
#define UMC_kernelize(callret...)    ({ error_t uk_ret = _UMC_kernelize(callret); \
					if (uk_ret < 0) \
					    sys_warning("%s returned %d", #callret, uk_ret); \
					uk_ret; \
				     })
#define UMC_kernelize64(callret...)  ({ error_t uk64_ret = _UMC_kernelize64(callret); \
					if (uk64_ret < 0) \
					    sys_warning("%s returned %d", #callret, uk64_ret); \
					uk64_ret; \
				     })
#endif

#define PTR_ERR(ptr)			((intptr_t)(ptr))
#define ERR_PTR(err)			((void *)(intptr_t)(err))
#define IS_ERR(ptr)			unlikely((unsigned long)(void *)(ptr) \
							> (unsigned long)(-4096))
#define IS_ERR_OR_NULL(ptr)		(unlikely(!ptr) || IS_ERR(ptr))

#define	ERESTARTSYS			512
#define ENOTSUPP			ENOTSUP

#define random32()			(random())  //XXX

static inline void
get_random_bytes(void * addr, int len)
{
    char * p = addr;
    int i;
    for (i = 0; i < len; i++)
	p[i] = random();
}

typedef unsigned int			fmode_t;
typedef unsigned short			umode_t;

#define FMODE_READ			0x01
#define FMODE_WRITE			0x02
#define FMODE_NDELAY			0x40
#define FMODE_EXCL			0x80

#define capable(cap)			(geteuid() == 0)    //XXX
#define CAP_SYS_ADMIN			21

/*** Time ***/

extern struct timezone sys_tz;

static inline struct timespec
ns_to_timespec(unsigned long ns)
{
    struct timespec ts = { };
    ts.tv_sec  = (long)(ns / 1000000000ul);
    ts.tv_nsec = (long)(ns % 1000000000ul);
    return ts;
}

static inline struct timeval
ns_to_timeval(unsigned long ns)
{
    struct timespec ts = ns_to_timespec(ns);
    struct timeval tv;
    tv.tv_sec = ts.tv_sec;
    tv.tv_usec = ts.tv_nsec / 1000;
    return tv;
}

#define NSEC_PER_USEC			1000L
#define NSEC_PER_MSEC			1000000L
#define NSEC_PER_SEC			1000000000L
#define USEC_PER_SEC			1000000L
#include <linux/ktime.h>

#define ktime(t)			((ktime_t){ .tv64 = (t) })
#define ktime_get()			ktime(sys_time_now() / (sys_time_hz()/1000000000L))
#define ktime_get_real() ({ \
    struct timespec _t;							\
    clock_gettime(CLOCK_REALTIME, &_t);					\
    ktime(_t.tv_sec*1L*1000*1000*1000 + _t.tv_nsec);			\
})

#define jiffies				( sys_time_now() / (sys_time_hz()/HZ) )

#define SYS_TIME_MAX			((unsigned long)LONG_MAX)
#define JIFFY_MAX			INT_MAX

#define msecs_to_jiffies(ms)		((unsigned long)(ms) * HZ / (1000))

#define jiffies_of_sys_time(t)		( (unsigned long)(t) / (sys_time_hz()/HZ) )

#define jiffies_to_sys_time(j) \
	    ( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
								* sys_time_hz() / HZ )

#define jiffies_to_msecs(j) \
	    (int)( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
								* 1000ul / HZ )

#define jiffies_to_usecs(j) \
	    ( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
							       * 1000ul * 1000ul / HZ )

#define sys_time_abs_of_jdelta(jdelta) \
({ \
    sys_time_t now = sys_time_now(); \
    sys_time_t _t_end = now + jiffies_to_sys_time(jdelta); \
    if (time_before(_t_end, now)) \
	_t_end = SYS_TIME_MAX; /* overflow */ \
    _t_end; \
})

//XXX Check all these time comparisons wrt signed vs. unsigned, and overflow
#define time_after(x, y)		((long)((x) - (y)) > 0)
#define time_after_eq(x, y)		((long)((x) - (y)) >= 0)
#define time_before(x, y)		time_after((y), (x))
#define time_before_eq(x, y)		time_after_eq((y), (x))

/* Who thought it was a good idea to declare the kernel version of tm.tm_year as type long?? */
/* Kernel version from include/linux/time.h */
struct tm {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        long tm_year;
        int tm_wday;
        int tm_yday;
};

/* libc version from x86_64-linux-gnu/bits/types/struct_tm.h */
struct tm_libc			/* ISO C `broken-down time' structure.  */
{
	int tm_sec;		/* Seconds.     [0-60] (1 leap second) */
	int tm_min;		/* Minutes.     [0-59] */
	int tm_hour;		/* Hours.       [0-23] */
	int tm_mday;		/* Day.         [1-31] */
	int tm_mon;		/* Month.       [0-11] */
	int tm_year;		/* Year - 1900.  */
	int tm_wday;		/* Day of week. [0-6] */
	int tm_yday;		/* Days in year.[0-365] */
	int tm_isdst;		/* DST.         [-1/0/1]*/
	long int tm_gmtoff;	/* Seconds east of UTC.  */
	const char *tm_zone;	/* Timezone abbreviation.  */
};

static inline void
time_to_tm(time_t secs, int ofs, struct tm * result)
{
    time_t total = secs + ofs;
    struct tm_libc tm_libc;
    localtime_r(&total, (void *)&tm_libc);  /* ugh */
    result->tm_sec =	    tm_libc.tm_sec;
    result->tm_min =	    tm_libc.tm_min;
    result->tm_hour =	    tm_libc.tm_hour;
    result->tm_mday =	    tm_libc.tm_mday;
    result->tm_mon =	    tm_libc.tm_mon;
    result->tm_year = (long)tm_libc.tm_year;
    result->tm_wday =	    tm_libc.tm_wday;
    result->tm_yday =	    tm_libc.tm_yday;
}

/*** Strings ***/

static inline char *
strnchr(string_t str, size_t strmax, int match)
{
    while (strmax && *str) {
	if (*str == match) return _unconstify(str);
	++str;
	--strmax;
    }
    return NULL;	/* not found */
}

/*** Modules ***/

#ifndef THIS_MODULE
extern struct module UMC_module;
#define THIS_MODULE (&UMC_module)
#endif

/* Externally-visible entry points for module init/exit functions */
#define module_init(fn)		 extern error_t _CONCAT(UMC_INIT_, fn)(void); \
					error_t _CONCAT(UMC_INIT_, fn)(void) { return fn(); }

#define module_exit(fn)		 extern void _CONCAT(UMC_EXIT_, fn)(void); \
					void _CONCAT(UMC_EXIT_, fn)(void) { fn(); }

#define MODULE_VERSION(str) static __attribute__((__unused__)) \
		string_t MODULE_VERSION = ("MODULE_VERSION='"str"_LIB'" \
						"(adapted to usermode)")

#define MODULE_LICENSE(str) static __attribute__((__unused__)) \
		string_t MODULE_LICENSE = ("MODULE_LICENSE='"str"'")

#define MODULE_AUTHOR(str) static __attribute__((__unused__)) \
		string_t _CONCAT(MODULE_AUTHOR, __LINE__) = \
			    ("MODULE_AUTHOR='"str"'\nUsermode adaptations by DAB")

#define MODULE_DESCRIPTION(str) static __attribute__((__unused__)) \
		string_t MODULE_DESCRIPTION = ("MODULE_DESCRIPTION='"str"'")

#define MODULE_NAME_LEN			56
struct modversion_info { unsigned long crc; char name[MODULE_NAME_LEN]; };
struct module { char name[MODULE_NAME_LEN]; string_t version; };

#define module_param_string(h1, h2, size_h2, mode)  /* */
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major)	    /* */

#define MODULE_INFO(ver, str)		/* */
#define MODULE_PARM_DESC(var, desc)	/* */

#define get_module_info(arg)		(-EINVAL)
#define try_module_get(module)		true
#define request_module(a, b)		DO_NOTHING()
#define module_put(module)		DO_NOTHING()

extern error_t UMC_init(const char *);	/* usermode_lib.c */
extern error_t UMC_exit(void);

typedef struct kernel_cap_struct { } kernel_cap_t;

struct kernel_param {			/* unused */
    unsigned int		      * arg;
};

#define EXPORT_SYMBOL(sym)		/* */
#define EXPORT_SYMBOL_GPL(sym)		/* */

/*** Memory ***/

struct sysinfo;
extern void si_meminfo(struct sysinfo *si);

#define __CACHE_LINE_BYTES		64  /* close enough */
#define SMP_CACHE_BYTES			__CACHE_LINE_BYTES
#define ____cacheline_aligned		__attribute__((aligned(__CACHE_LINE_BYTES)))
#define ____cacheline_aligned_in_smp	____cacheline_aligned

#define object_is_on_stack(addr)	false
#define is_vmalloc_addr(addr)		false	/* no special-case memory */

/* Allocations in usermode always succeed (or panic in the allocator) */
/* The GFP flags are almost entirely ignored, but (e.g.) DRBD overloads them */
#define __GFP_DMA		((gfp_t)0x01u)
#define __GFP_HIGHMEM		((gfp_t)0x02u)
// #define __GFP_DMA32		((gfp_t)0x04u)
// #define __GFP_MOVABLE	((gfp_t)0x08u)
#define __GFP_WAIT		((gfp_t)0x10u)
#define __GFP_HIGH		((gfp_t)0x20u)
#define __GFP_IO		((gfp_t)0x40u)
#define __GFP_FS		((gfp_t)0x80u)
// #define __GFP_COLD		((gfp_t)0x100u)
#define __GFP_NOWARN		((gfp_t)0x200u)
// #define __GFP_REPEAT		((gfp_t)0x400u)
#define __GFP_NOFAIL		((gfp_t)0x800u)
#define __GFP_NORETRY		((gfp_t)0x1000u)
// #define __GFP_COMP		((gfp_t)0x4000u)
#define __GFP_ZERO		((gfp_t)0x8000u)    /* not ignored */
// #define __GFP_NOMEMALLOC	((gfp_t)0x10000u)
#define __GFP_HARDWALL		((gfp_t)0x20000u)
// #define __GFP_THISNODE	((gfp_t)0x40000u)
// #define __GFP_RECLAIMABLE	((gfp_t)0x80000u)
// #define __GFP_NOTRACK	((gfp_t)0x200000u)

#define GFP_NOWAIT		(GFP_ATOMIC & ~__GFP_HIGH)
#define GFP_ATOMIC		(__GFP_HIGH)
#define GFP_NOIO		(__GFP_WAIT)
#define GFP_KERNEL		(__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_HIGHUSER		(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM)
#define GFP_DMA			__GFP_DMA
// #define GFP_NOFS		(__GFP_WAIT | __GFP_IO)
// #define GFP_TEMPORARY	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_RECLAIMABLE)
// #define GFP_USER		(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
// #define GFP_HIGHUSER_MOVABLE (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM | __GFP_MOVABLE)

#define KERNEL_DS			IGNORED
#define get_fs()			IGNORED
#define get_ds()			IGNORED

#define set_fs(newfs)			DO_NOTHING( _USE(newfs) )

#define vmalloc(size)			sys_mem_alloc(size)
#define vzalloc(size)			sys_mem_zalloc(size)
#define vrealloc(oaddr, nsize)		sys_mem_realloc((oaddr), (nsize))
#define vfree(addr)			sys_mem_free(addr)

#define kalloc(size, gfp)		(((gfp) & __GFP_ZERO) ? vzalloc(size) : vmalloc(size))
#define kzalloc(size, gfp)		(_USE(gfp), vzalloc(size))
#define kzalloc_node(size, gfp, nodeid) (_USE(nodeid), kzalloc((size), (gfp)))

#define krealloc(oaddr, nsize, gfp)	(_USE(gfp), vrealloc((oaddr), (nsize)))

#define kfree(addr)			do { if (likely(addr)) vfree(addr); } while (0)

#define kmalloc(size, gfp)		kalloc((size), (gfp))
#define kmalloc_track_caller(size, gfp)	kalloc((size), (gfp))
#define kcalloc(count, size, gfp)	kzalloc((count) * (size), (gfp))

#define __vmalloc(size, gfp, prot)	(_USE(prot), kalloc((size), (gfp)))

#ifndef PAGE_SHIFT
#define PAGE_SHIFT			12U	/* need not match real kernel */
#endif

#define PAGE_SIZE			(1U<<PAGE_SHIFT)
#define PAGE_MASK			(~((unsigned long)PAGE_SIZE - 1))

#define PAGE_ALIGN(size)		ALIGN((size), PAGE_SIZE)

/* These "page" functions actually work on addresses, not struct page */
#define __get_free_page(gfp)		kalloc(PAGE_SIZE, (gfp))
#define __get_free_pages(gfp, order)	kalloc(PAGE_SIZE << (order), (gfp))
#define get_zeroed_page(gfp)		kzalloc(PAGE_SIZE, (gfp))
#define copy_page(dst, src)		memcpy((dst), (src), PAGE_SIZE)
#define nth_page(page, n)		((void *)(page) + (n)*PAGE_SIZE)
#define pages_free(addr, order)		kfree(addr)

#define free_page(addr)			free_pages((addr), 0)
#define free_pages(addr, order)		kfree((void *)addr)

//XXX ADD mem_buf_allocator_set() to the sys_services API
extern void _mem_buf_allocator_set(void * buf, sstring_t caller_id);
#define mem_buf_allocator_set(buf, caller_id) _mem_buf_allocator_set((buf), (caller_id))

/* Note: this is not about the simulated kernel page cache */
#ifndef PAGE_CACHE_SHIFT
/* In theory this can be different from PAGE_SHIFT, but I'm not sure all the code is correct */
#define PAGE_CACHE_SHIFT		PAGE_SHIFT
#endif

#define PAGE_CACHE_SIZE			(1UL<<PAGE_CACHE_SHIFT)
#define PAGE_CACHE_MASK			(~(PAGE_CACHE_SIZE-1))

/* kmem_cache */

#define kmem_cache			sys_buf_cache

#ifndef KMEM_CACHE_ALIGN_MIN
#define KMEM_CACHE_ALIGN_MIN		__CACHE_LINE_BYTES
#endif

#ifndef KMEM_CACHE_ALIGN
#define KMEM_CACHE_ALIGN(size)		((size) >= PAGE_SIZE ? PAGE_SIZE : \
					 (size) >= 512 ? 512 : KMEM_CACHE_ALIGN_MIN)
#endif

#define SLAB_HWCACHE_ALIGN		0x00002000U	/* a flag bit, not a size */

#define KMEM_CACHE(s, flags) \
	    kmem_cache_create(#s, sizeof(struct s), __alignof__(struct s), (flags), 0)

#define kmem_cache_alloc_node(cache, gfp, nodeid) (_USE(nodeid), kmem_cache_alloc(cache, (gfp)))

#define kmem_cache_alloc(cache, gfp)	(((gfp) & __GFP_ZERO) ? (void *)sys_buf_zalloc(cache) \
							      : (void *)sys_buf_alloc(cache))
#define kmem_cache_zalloc(cache, gfp)	(_USE(gfp), (void *)sys_buf_zalloc(cache))
#define kmem_cache_free(cache, ptr)	(_USE(cache), sys_buf_drop((sys_buf_t)(ptr)))
#define kmem_cache_size(cache)		((unsigned)(-1));   //XXXX bigger than you need
					//XXX ADD kmem_cache_size() to the sys_services API

static inline void
kmem_cache_destroy(struct kmem_cache * cache)
{
    error_t err = sys_buf_cache_destroy(cache);
    if (err == E_OK)
	return;
    sys_warning("kmem_cache not empty");
}

//XXX Limitation: kmem_cache doesn't currently support flags or constructor
static inline struct kmem_cache *
kmem_cache_create(string_t name, size_t size, size_t req_align,
		   unsigned int flags, void * constructor)
{
    size_t min_align;
    assert_eq(constructor, NULL);   /* XXX kmem_cache constructor unsupported */

    if (flags & SLAB_HWCACHE_ALIGN) min_align = __CACHE_LINE_BYTES;
    else min_align = sizeof(uint64_t);

    if (min_align < req_align) min_align = req_align;

    return sys_buf_cache_create(name, size, min_align);
}

/* mempool */

typedef	struct mempool {
    void		  * pool_data;	/* e.g. kmem_cache or mp */
    void		  * pool_data2;	//XXX
    void		  * pool_data3;	//XXX
    void		  * (*alloc_fn)(gfp_t, void * pool_data);
    void		    (*free_fn)(void * elem, void * pool_data);
    void		    (*destroy_fn)(struct mempool *);
    unsigned long	    private;
    sstring_t		    name;
} mempool_t;

/* Allocate from the mempool */
static inline void *
mempool_alloc(mempool_t * mp, gfp_t gfp)
{
    return mp->alloc_fn(gfp, mp->pool_data);
}

/* Free to the mempool */
static inline void
mempool_free(void * addr, mempool_t * mp)
{
    if (addr)
	mp->free_fn(addr, mp->pool_data);
    else
	sys_backtrace("Attempt to mempool_free(NULL)");
}

/* Destroy the mempool (but empty it first) */
static inline void
mempool_destroy(mempool_t * mp)
{
    if (mp->destroy_fn)
	mp->destroy_fn(mp);
    else
	record_free(mp);
}

/* Create a mempool: pool_data passed to alloc/free functions */
static inline mempool_t *
mempool_create(int min_nr, void * (*alloc_fn)(gfp_t, void *),
		void (*free_fn)(void *, void *), void * pool_data)
{
    assert(alloc_fn != NULL);
    assert(free_fn != NULL);
    mempool_t * mp = record_alloc(mp);
    mp->pool_data = pool_data;
    mp->alloc_fn = alloc_fn;
    mp->free_fn = free_fn;
    //XXX should allocate and then free min_nr instances to get them in kcache
    return mp;
}

/* slab_pool allocates from a kmem_cache provided on create */

static inline void *
mempool_alloc_slab(gfp_t gfp, void * kcache_v)
{
    struct kmem_cache * kcache = kcache_v;
    return kmem_cache_alloc(kcache, gfp);
}

static inline void
mempool_free_slab(void * elem, void * kcache_v)
{
    struct kmem_cache * kcache = kcache_v;
    kmem_cache_free(kcache, elem);
}

static inline void
_slab_pool_destroy(mempool_t * mp)
{
    /* Caller of mempool_create_slab_pool() owns the kmem_cache */
    record_free(mp);
}

#define mempool_create_slab_pool(min_nr, order) \
	    _mempool_create_slab_pool((min_nr), (order), FL_STR)

static inline mempool_t *
_mempool_create_slab_pool(int min_nr, struct kmem_cache * kcache, sstring_t caller_id)
{
    mempool_t * mp = mempool_create(min_nr, mempool_alloc_slab,
					     mempool_free_slab, (void *)kcache);
    mp->name = caller_id;
    mp->destroy_fn = _slab_pool_destroy;
    mem_buf_allocator_set(mp, caller_id);
    return mp;
}

/* Create a kmem_cache of a given size and put a slab_pool around it */

static inline void
_mempool_destroy_kmalloc_pool(mempool_t * mp)
{
    kmem_cache_destroy(mp->pool_data);
    record_free(mp);
}

static inline mempool_t *
_mempool_create_kmalloc_pool(int min_nr, size_t size, sstring_t caller_id)
{
    mempool_t * mp = _mempool_create_slab_pool(min_nr,
			    kmem_cache_create("kmalloc_pool",
					      size, KMEM_CACHE_ALIGN(size),
					      IGNORED, IGNORED),
			    caller_id);
    mp->destroy_fn = _mempool_destroy_kmalloc_pool;
    return mp;
}

#define mempool_create_kmalloc_pool(min_nr, size) \
	    _mempool_create_kmalloc_pool((min_nr), (size), FL_STR)

#define kmemdup(addr, len, gfp)		memcpy(kalloc((len), (gfp)), (addr), (len))
#define kstrdup(string, gfp)		kmemdup((string), 1+strlen(string), (gfp))
#define vstrdup(string)			kstrdup((string), IGNORED)
#define strlcpy(dst, src, size)		(dst[(size)-1] = '\0',		    \
					 strncpy((dst), (src), (size)-1),   \
					 UMC_size_t_JUNK=strlen(src))

#define access_ok(type, addr, size)	true
#define copy_from_user(dst, src, len)	(memcpy((dst), (src), (len)), E_OK)
#define copy_to_user(dst, src, len)	(memcpy((dst), (src), (len)), E_OK)
#define get_user(id, ptr)		(((id) = *(ptr)), E_OK)
#define __get_user(id, ptr)		(((id) = *(ptr)), E_OK)
#define put_user(val, ptr)		((*(ptr) = (val)), E_OK)

#define get_user_pages(a,b,c,d,e,f,g,h)	E_OK	/* pages always mapped in usermode */

/*** Formatting and logging ***/

/* string_concat_free() appends suffix string to prefix string, CONSUMING BOTH and returning
 * the concatination -- either or both strings may be NULL -- if both, NULL is returned.
 */
//XXX ADD mem_string_concat_free() to the sys_services API
#define string_concat_free(prefix, suffix) mem_string_concat_free((prefix), (suffix), FL_STR)
extern string_t mem_string_concat_free(string_t const prefix, string_t const suffix,
							sstring_t const caller_id);

#define scnprintf(buf, bufsize, fmtargs...) snprintf((buf), (bufsize), fmtargs)
#define vscnprintf(buf, bufsize, fmt, va)  vsnprintf((buf), (bufsize), fmt, va)

#define kasprintf(gfp, fmt, args...)	sys_sprintf(fmt, ##args)
#define kvasprintf(gfp, fmt, va)	sys_vsprintf(fmt, va)
#define panic(fmtargs...)		sys_panic(fmtargs)

#ifndef KBUILD_MODNAME
#define _MODNAME			""
#else
#define _MODNAME			KBUILD_MODNAME ": "
#endif

#define pr_warn_ratelimited(fmtargs...)	pr_warning(fmtargs) /* no ratelimit */

#define KERN_LOC_FIELDS			current->pid, __func__, __LINE__, __FILE__
#define KERN_LOC_FMT			"[%u] %s:%u (%s):"

/*** Usermode helper ***/

#define UMH_NO_WAIT			0
#define UMH_WAIT_PROC			2	/* wait for the process to complete */

/* Call another usermode program */
static inline int
call_usermodehelper(const char * progpath, char * argv[], char * envp[], int waitflag)
{
    pid_t cpid = fork();
    if (cpid) {
	int status;
	if (waitflag == UMH_NO_WAIT)
	    return E_OK;

	waitpid(cpid, &status, 0);
	if (!WIFEXITED(status))
	    printk("usermodehelper '%s' abnormal exit\n", progpath);
	else if (WEXITSTATUS(status))
	    printk("usermodehelper '%s' exit code %u\n", progpath, WEXITSTATUS(status));
	else
	    return E_OK;

	return -1;
    }
    execve(progpath, argv, envp);
    printk("usermodehelper '%s' not found\n", progpath);
    exit(99);
}

/********** Barriers, Atomics, Locking **********/

#define __barrier()			__sync_synchronize()
#define smp_mb()			__barrier()
#define smp_rmb()			__barrier()
#define smp_wmb()			__barrier()

#define	smp_mb__before_atomic_dec()	__barrier()	//XXX needed?
#define	smp_mb__after_atomic_dec()	__barrier()	//XXX needed?
#define	smp_mb__after_atomic_inc()	__barrier()	//XXX needed?

#define ATOMIC_INIT(n)			((atomic_t){ .counter = (n) })

					//XXX Figure out which of these barriers isn't needed
#define atomic_get(ptr)			({ __barrier(); int32_t ag_ret = (ptr)->counter; __barrier(); ag_ret; })
#define atomic_set(ptr, val)		do { __barrier(); (ptr)->counter = (val); __barrier(); } while (0)

/* Bitwise atomics return the OLD value */
#define atomic_or(n, ptr)		__sync_fetch_and_or( &(ptr)->counter, (n))
#define atomic_and(n, ptr)		__sync_fetch_and_and(&(ptr)->counter, (n))

/* Arithmetic atomics return the NEW value */
#define atomic_add_return(n, ptr)	__sync_add_and_fetch(&(ptr)->counter, (n))
#define atomic_sub_return(n, ptr)	__sync_sub_and_fetch(&(ptr)->counter, (n))
#define atomic_inc_return(ptr)		atomic_add_return(1, (ptr))
#define atomic_dec_return(ptr)		atomic_sub_return(1, (ptr))

#define atomic_read(ptr)		atomic_get(ptr)
#define atomic_add(n, ptr)		atomic_add_return((n), (ptr))
#define atomic_sub(n, ptr)		atomic_sub_return((n), (ptr))
#define atomic_inc(ptr)			atomic_inc_return(ptr)
#define atomic_dec(ptr)			atomic_dec_return(ptr)

#define atomic_dec_and_test(ptr)	(!atomic_dec_return(ptr)) /* true if result *IS* zero */
#define atomic_sub_and_test(n, ptr)	(!atomic_sub_return((n), (ptr)))

/* Installs the new 8-byte value at addr and returns the old value */
#define xchg(addr, newv) ({ \
	    typeof(*addr) ____newv = (newv); \
	    typeof(*addr) ____oldv; \
	    __atomic_exchange((addr), &(____newv), &(____oldv), __ATOMIC_SEQ_CST); \
	    ____oldv; \
})

#define atomic_xchg(atom, newv) xchg(&(atom)->counter, (newv))

/* Returns the value of the atomic prior to the instruction */
#define cmpxchg(addr, oldv, newv) \
		__sync_val_compare_and_swap((addr), (oldv), (newv))

#define atomic_cmpxchg(atom, oldv, newv) \
		__sync_val_compare_and_swap(&(atom)->counter, (oldv), (newv))

static inline bool
_atomic_cas(atomic_t * atomic, int32_t const expected, int32_t const newval)
{
    return __sync_bool_compare_and_swap(&atomic->counter, expected, newval);
}

static inline int
atomic_add_unless(atomic_t * ptr, int increment, int unless_match)
{
    int oldval;
    do {
	oldval = atomic_get(ptr);
	if (unlikely(oldval == unless_match)) break;
    } while (!_atomic_cas(ptr, oldval, oldval + increment));

    return oldval;
}

struct spinlock;
extern int _atomic_dec_and_lock(atomic_t * atomic, struct spinlock * lock);
#define atomic_dec_and_lock(atomic, lock) _atomic_dec_and_lock(atomic, lock)

/*** Bitmap (non-atomic) ***/

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

/*** spin lock ***/

#define lock_trace(args...)	//	trace(args)

#define UMC_LOCK_CHECKS	    /* do lock checks in all builds */

#if 1	    //XXX _SPINWAITING()
//XXXX change this to only yield after some number (like 100) of spins
#define _SPINWAITING()			usleep(1)
#else
#if defined(__i386__) || defined(__x86_64__)
  /* Avoid clogging CPU pipeline with lock fetches for several times around a spinloop */
  #ifdef NVALGRIND
    #define _SPINWAITING()		__builtin_ia32_pause()
  #else
    #include <valgrind.h>
    /* There seems to be some problem with valgrind looping with this instruction XXX */
    #define _SPINWAITING()   do { if (!RUNNING_ON_VALGRIND) __builtin_ia32_pause(); } while (0)
  #endif
#else
  #define _SPINWAITING()		DO_NOTHING()
#endif
#endif

/* Multi-Reader/Single-Writer SPIN lock -- favors readers, recursive read OK */
typedef struct rwlock {
    atomic_t	   volatile count;	/* units available to take */
#ifdef UMC_LOCK_CHECKS
    sys_thread_t   volatile owner;	/* exclusive holder (writer), if any */
#endif
    sstring_t		    name;	/* logging string */
} rwlock_t;				//XXX add some spinlock stats

#define _RWLOCK_FMT		"name=%s owner=%p[%u]%s count=%d"
#define _RWLOCK_FIELDS(RW)	(RW)->name, (RW)->owner, (RW)->owner?(RW)->owner->tid:0, \
				(RW)->owner?(RW)->owner->name:"", atomic_read(&(RW)->count)

/* (1<<16) can support up to 64K concurrent readers and 32K contending writers */
#define _RW_LOCK_WR_COUNT		(1UL<<16)   /* count required for writing */
#define _RW_LOCK_RD_COUNT		1	    /* count required for reading */

#define RW_LOCK_UNLOCKED(rwname)	{ .count = { _RW_LOCK_WR_COUNT }, .name = #rwname }
#define DEFINE_RWLOCK(rw)		struct rwlock rw = RW_LOCK_UNLOCKED(#rw)
#define rwlock_init(rw)			(*(rw) = (rwlock_t)RW_LOCK_UNLOCKED(#rw))

static inline void
rwlock_assert_writer(rwlock_t * rw)
{
#ifdef UMC_LOCK_CHECKS
    verify_le(atomic_read(&rw->count), 0, "Writer not exclusive??");
    verify_eq(sys_thread_current(), rw->owner, "%s expected to own lock '%s' owned instead by %s",
	      sys_thread_name(sys_thread_current()), rw->name, sys_thread_name(rw->owner));
#endif
}

static inline void
rwlock_assert_readlocked(rwlock_t * rw)
{
#ifdef UMC_LOCK_CHECKS
    expect_lt(atomic_read(&rw->count), _RW_LOCK_WR_COUNT, "%s is not locked as expected", rw->name);
    expect_gt(atomic_read(&rw->count), 0, "%s is WRITE locked during read op", rw->name);
#endif
}

/* Returns true if ntake acquired, else false (zero count taken) */
static inline error_t
rwlock_take_try(rwlock_t * rw, uint32_t ntake)
{
    /* Try to take the requested count */
    if (unlikely(atomic_sub_return(ntake, &rw->count) < 0)) {
	/* Overdraft -- insufficient count available to satisfy "take" request */
	atomic_add(ntake, &rw->count);	/* give back our overdraft of rw->count */
#ifdef UMC_LOCK_CHECKS
	verify(rw->owner != sys_thread_current(),
		"Thread attempts to acquire a rw_spinlock it already holds");
#endif
	return false;
    }
    /* Successfully took (ntake) from lock available count */
#ifdef UMC_LOCK_CHECKS
    verify_eq(rw->owner, NULL);	    /* we got it, so nobody else better own it exclusively */
    if (ntake >= _RW_LOCK_WR_COUNT) {
	/* We're not merely reading -- record as exclusive owner */
	rw->owner = sys_thread_current();
    }
#endif
    lock_trace("'%s' (%u) takes %u for %s from spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  ntake, ntake > _RW_LOCK_RD_COUNT ? "WRITE" : "READ", rw->name, rw);
    return true;
}

#define read_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_RD_COUNT)
#define write_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_WR_COUNT)

#define read_lock(rw)			while (!read_lock_try(rw)) _SPINWAITING()
#define write_lock(rw)			while (!write_lock_try(rw)) _SPINWAITING()

static inline void
rwlock_drop(rwlock_t * rw, uint32_t ndrop)
{
    lock_trace("'%s' (%u) returns %u (%s) to spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  ndrop, ndrop > _RW_LOCK_RD_COUNT ? "WRITE" : "READ", rw->name, rw);
#ifdef UMC_LOCK_CHECKS
    if (unlikely(ndrop > _RW_LOCK_RD_COUNT)) {
	rwlock_assert_writer(rw);
	rw->owner = NULL;
    }
    int32_t new_count = atomic_add_return(ndrop, &(rw)->count);
    verify_le(new_count, _RW_LOCK_WR_COUNT, "double unlock?");
#else
    atomic_add(ndrop, &(rw)->count);
#endif
}

#define read_unlock(rw)			rwlock_drop((rw), _RW_LOCK_RD_COUNT)
#define write_unlock(rw)		rwlock_drop((rw), _RW_LOCK_WR_COUNT)
#define write_downgrade(rw)		rwlock_drop((rw), _RW_LOCK_WR_COUNT - _RW_LOCK_RD_COUNT)

/* Lock by itself should suffice because the softirq thread is never (virtually) "local" */
#define write_lock_bh(rw)		write_lock(rw)
#define write_unlock_bh(rw)		write_unlock(rw)

/* "local" functions shouldn't need to do anything beyond what associated lock accomplishes */
#define local_bh_disable()		DO_NOTHING()
#define local_bh_enable()		DO_NOTHING()
#define local_irq_save(saver)		DO_NOTHING( _USE(saver) )
#define local_irq_restore(saver)	DO_NOTHING()
#define local_irq_disable()		DO_NOTHING()
#define local_irq_enable()		DO_NOTHING()
#define irqs_disabled()			false

#define preempt_disable()		DO_NOTHING()
#define preempt_enable()		DO_NOTHING()

/* Mutex SPIN lock */
/* Implement using a pthread_mutex and _trylock(), so it can work with pthread_cond_t */
typedef struct spinlock {
#ifdef UMC_LOCK_CHECKS
    sys_thread_t   volatile owner;	/* current locker */
#endif
    pthread_mutex_t	    plock;
    sstring_t		    name;
    sstring_t		    whence;	/* last locker */
} spinlock_t;				//XXX add some spinlock stats

#define SPINLOCK_UNLOCKED(lock)		{ .plock = PTHREAD_MUTEX_INITIALIZER, .name = #lock }
#define DEFINE_SPINLOCK(lock)		spinlock_t lock = SPINLOCK_UNLOCKED(#lock)
#define spin_lock_init(lock)		(*(lock) = (spinlock_t)SPINLOCK_UNLOCKED(#lock))
#define assert_spin_locked(lock)	spin_lock_assert_holding(lock)

static inline void
spin_lock_assert_holding(spinlock_t * lock)
{
#ifdef UMC_LOCK_CHECKS
    assert(lock);
    verify_eq(sys_thread_current(), lock->owner, "%s expected to own lock '%s' owned instead by %s taken at %s",
	      sys_thread_name(sys_thread_current()), lock->name, sys_thread_name(lock->owner), lock->whence);
#endif
}

//XXX yuck, these are used on mutex locks too
#ifdef UMC_LOCK_CHECKS
#define SPINLOCK_CLAIM(lock)	verify_eq((lock)->owner, NULL); (lock)->owner = sys_thread_current();
#define SPINLOCK_DISCLAIM(lock)	spin_lock_assert_holding(lock); (lock)->owner = NULL;
#else
#define SPINLOCK_CLAIM(lock)	DO_NOTHING()
#define SPINLOCK_DISCLAIM(lock)	DO_NOTHING()
#endif

/* Returns true if lock acquired, else false */
#define spin_lock_try(lock)		_spin_lock_try((lock), FL_STR)
static inline error_t
_spin_lock_try(spinlock_t * lock, sstring_t whence)
{
    error_t err = pthread_mutex_trylock(&lock->plock);
    if (unlikely(err != 0)) {
#ifdef UMC_LOCK_CHECKS
	if (err == EBUSY) {
	    verify(lock->owner != sys_thread_current(),
		"Thread %d ('%s') attempts to acquire a spinlock '%s' (%p) it already holds (%p) taken at %s",
		sys_thread_current()->tid, sys_thread_name(sys_thread_current()),
		lock->name, lock, lock->owner, lock->whence);
	} else
	    sys_warning("Error %s (%d) on pthread_mutex_trylock(%s) from %s",
		    strerror(err), err, lock->name, whence);
#endif
	return false;
    }
    /* Successfully acquired lock */
    SPINLOCK_CLAIM(lock);
    lock->whence = whence;
    lock_trace("'%s' (%u) takes spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  lock->name, lock);
    return true;
}

#define spin_lock(lock)		_spin_lock((lock), FL_STR)
static inline void
_spin_lock(spinlock_t * lock, sstring_t whence)
{
    while (!_spin_lock_try(lock, whence)) _SPINWAITING();
}

//XXX spin_lock_nested() support: change the pthread lock type to RECURSIVE ?
#define spin_lock_nested(lock, subclass)    UMC_STUB(spin_lock_nested) //XXXXXX

static inline void
spin_unlock(spinlock_t * lock)
{
    lock_trace("'%s' (%u) drops spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  rw->name, rw);
    SPINLOCK_DISCLAIM(lock);
    pthread_mutex_unlock(&lock->plock);
}

/* Lock by itself should suffice */
#define spin_lock_bh			spin_lock
#define spin_lock_irq			spin_lock
#define spin_lock_irqsave(lock, save)	do { _USE(save); spin_lock(lock); } while (0)

#define spin_lock_bh_assert_holding(l)	spin_lock_assert_holding(l)
#define spin_lock_irq_assert_holding(l)	spin_lock_assert_holding(l)

#define spin_unlock_bh(lock)		spin_unlock(lock)
#define spin_unlock_irq(lock)		spin_unlock(lock)
#define spin_unlock_irqrestore(lock, save)  spin_unlock(lock)

/*** Sleepable mutex lock ***/
typedef struct mutex {
    sys_thread_t               volatile owner;	/* the exclusive holder */
    pthread_mutex_t		        lock;
    sstring_t				name;
    sstring_t				whence;	/* FILE:LINE of last locker */
    //XXX add some mutex stats
} mutex_t;

#define MUTEX_UNLOCKED(mname)		((struct mutex){ .lock = PTHREAD_MUTEX_INITIALIZER, .name = #mname })
#define DEFINE_MUTEX(m)			struct mutex m = MUTEX_UNLOCKED(#m)
#define mutex_init(m)			do { *(m) = MUTEX_UNLOCKED(#m); } while (0)
#define mutex_destroy(m)		pthread_mutex_destroy(&(m)->lock)

static inline void
mutex_assert_holding(mutex_t * m)
{
#ifdef UMC_LOCK_CHECKS
    verify_eq(sys_thread_current(), m->owner, "%s expected to own mutex '%s' owned instead by %s taken at %s",
	      sys_thread_name(sys_thread_current()), m->name, sys_thread_name(m->owner), m->whence);
#endif
}

/* Try to acquire a mutex lock -- returns true if lock acquired, false if not */
#define mutex_trylock(m)		_mutex_trylock((m), FL_STR)
static inline error_t
_mutex_trylock(mutex_t * m, sstring_t whence)
{
    if (unlikely(pthread_mutex_trylock(&m->lock))) {
	/* Can't get the lock because it is held by somebody */
	return false;
    }
#ifdef UMC_LOCK_CHECKS
    verify_eq(m->owner, NULL);
    m->owner = sys_thread_current();
#endif
    m->whence = whence;
    lock_trace("'%s' (%u) at %s acquires mutex '%s' (%p)",
	  sys_thread_name(m->owner), sys_thread_num(m->owner), whence, m->name, m);
    return true;
}

/* Acquire a mutex lock -- attempt to avoid a context switch when wait time is short */
#define mutex_lock(m)			_mutex_lock((m), FL_STR)
static inline void
_mutex_lock(mutex_t * m, sstring_t whence)
{
    #define MUTEX_SPINS 100	/* Try this many spins before resorting to context switch */
    uint32_t spins = MUTEX_SPINS;
    while (--spins) {
	if (likely(_mutex_trylock(m, whence))) {
	    return;	/* got the lock */
	}
#ifdef UMC_LOCK_CHECKS
	verify(m->owner != sys_thread_current(),
		"Thread attempts to acquire a mutex it already holds, taken at %s", m->whence);
#endif
	_SPINWAITING();
    }

    /* We exhausted the time we're willing to spinwait -- give up the CPU */
#if 0	    // mutex wait time measurements
#if !OPTIMIZED
    sys_time_t const t_start = sys_time_now();
#endif
#endif
    /*** SLEEP ***/
    pthread_mutex_lock(&m->lock);
//XXXXX Use  pthread_mutex_timedlock(pthread_mutex_t *, struct timespec *);
//XXXXX	     with a check_interval to implement mutex_lock_interruptible()

    /*** AWAKE ***/
#ifdef UMC_LOCK_CHECKS
    verify_eq(m->owner, NULL);
    m->owner = sys_thread_current();
#endif

#if 0	    // mutex wait time measurements
#if !OPTIMIZED
    sys_time_t const t_delta = sys_time_now() - t_start;
    trace("'%s' (%u) at %s acquires mutex '%s' (%p) after sleeping %"PRIu64" ns",
	  sys_thread_name(m->owner), sys_thread_num(m->owner), whence, m->name, m, t_delta);
#else
    trace("'%s' (%u) at %s acquires mutex '%s' (%p) after sleeping",
	  sys_thread_name(sys_thread_current()),
	  sys_thread_num(sys_thread_current()), whence, m->name, m);
#endif
#endif
}

#define mutex_lock_interruptible(m)	(mutex_lock(m), E_OK)	//XXXXX

static inline void
mutex_unlock(mutex_t * m)
{
    mutex_assert_holding(m);
    lock_trace("'%s' (%u) drops mutex '%s' (%p)",
	  sys_thread_name(m->owner), sys_thread_num(m->owner), m->name, m);
    m->owner = NULL;
    pthread_mutex_unlock(&m->lock);
}

/* Use of this function is inherently racy */
static inline bool
mutex_is_locked(mutex_t * m)
{
    if (unlikely(!mutex_trylock(m))) {
	return true;	/* we couldn't get the mutex, therefore it is locked */
    }
    mutex_unlock(m);    /* unlock the mutex we just locked to test it */
    return false;	/* We got the mutex, therefore it was not locked */
}

/*** Sleepable semaphore ***/

#define trace_sema(fmtargs...)	//	sys_notice(fmtargs)
struct semaphore {
    sem_t				UM_sem;
    sys_thread_t			volatile owner;
    sstring_t				last_locker;
};

static inline error_t
sema_init(struct semaphore * sem, unsigned int val)
{
    return UMC_kernelize(sem_init(&sem->UM_sem, 0/*intra-process*/, val));
}

#define up(sem) UMC_up((sem), FL_STR)
static inline error_t
UMC_up(struct semaphore * sem, sstring_t whence)
{
    sem->owner = NULL;
    error_t err = UMC_kernelize(sem_post(&sem->UM_sem));
    trace_sema("%s: ++++++++++ UP(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
    return err;
}

#define down(sem) UMC_down((sem), FL_STR)
static inline error_t
UMC_down(struct semaphore * sem, sstring_t whence)
{
    trace_sema("%s: ========== DOWN(%p) %d-->...", whence, sem, *(int *)sem);
    error_t err = UMC_kernelize(sem_wait(&sem->UM_sem));
    trace_sema("%s: ---------- DOWN(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
    sem->owner = sys_thread_current();
    sem->last_locker = whence;
    return err;
}

#define down_trylock(sem) UMC_down_trylock((sem), FL_STR)
static inline error_t
UMC_down_trylock(struct semaphore * sem, sstring_t whence)
{
    error_t err = UMC_kernelize(sem_trywait(&sem->UM_sem));
    if (err == E_OK) {
	trace_sema("%s: ---------- DOWN_TRY(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
	sem->owner = sys_thread_current();
	sem->last_locker = whence;
    } else {
	trace_sema("%s: xxxxxxxxxx DOWN_TRY(%p)==%d err=%d", whence, sem, *(int *)sem, err);
    }
    return err;
}

/* Lock dependency checks */
/* Note: this macro gets invoked on both mutex locks and spin locks */
#define lockdep_assert_held(m)		assert_eq(sys_thread_current(), (m)->owner)
#define lockdep_is_held(m)		lockdep_assert_held(m)

/* Lockdep not implemented */
struct lock_class_key { };
struct lockdep_map { };
#define STATIC_LOCKDEP_MAP_INIT(name, key)		{ }
#define lockdep_set_class(a, b)				DO_NOTHING()
#define rwlock_acquire_read(map, subclass, trylock, IP)	DO_NOTHING()
#define lock_contended(map, IP)				DO_NOTHING()
#define lock_acquired(map, IP)				DO_NOTHING()
#define rwlock_release(map, n, IP)			DO_NOTHING()

#define __acquires(x)			/* */
#define __releases(x)			/* */
#define __acquire(x)			(void)0
#define __release(x)			(void)0

/*** RCU Synchronization (faked using rw_lock) ***/

extern rwlock_t				UMC_rcu_lock;	/* the global pseudo-RCU lock */

/* Embedded in each RCU-protected structure */
struct rcu_head {
    void				* next;
    void				(*func)(struct rcu_head *);
};

/* Readers */
#define rcu_read_lock()			read_lock(&UMC_rcu_lock)
#define rcu_read_unlock()		read_unlock(&UMC_rcu_lock)
#define _rcu_assert_readlocked()	rwlock_assert_readlocked(&UMC_rcu_lock)

/* These are only supposed to be used under rcu_read_lock(), right? XXX */
#define rcu_dereference(ptr)		({ /* _rcu_assert_readlocked(); */ (ptr); })

#define list_for_each_entry_rcu(p, h, m) /* _rcu_assert_readlocked(); */ \
					 list_for_each_entry((p), (h), m)

#define rcu_dereference_protected(p, c) ({ assert(c); (p); })

/* Writers */
#define UMC_rcu_write_lock()		write_lock(&UMC_rcu_lock)
#define UMC_rcu_write_unlock()		write_unlock(&UMC_rcu_lock)

#define rcu_assign_pointer(ptr, val)	do { UMC_rcu_write_lock(); \
					     (ptr) = (val); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_add_rcu(elem, list)	do { UMC_rcu_write_lock(); \
					     list_add(elem, list); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_add_tail_rcu(elem, list)	do { UMC_rcu_write_lock(); \
					     list_add_tail(elem, list); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_del_rcu(elem)		do { UMC_rcu_write_lock(); \
					     list_del(elem); \
					     UMC_rcu_write_unlock(); \
					} while (0)

extern struct rcu_head		      * UMC_rcu_cb_list;
extern spinlock_t			UMC_rcu_cb_list_lock;

#define call_rcu(head, fn)		do { (head)->func = fn; \
					     spin_lock(&UMC_rcu_cb_list_lock); \
					     (head)->next = UMC_rcu_cb_list; \
					     if (!UMC_rcu_cb_list) \
						wake_up(&UMC_rcu_cb_wake); \
					     UMC_rcu_cb_list = (head); \
					     spin_unlock(&UMC_rcu_cb_list_lock); \
					} while (0)

#define synchronize_rcu()		do { UMC_rcu_write_lock(); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define __rcu				/* neutralize some kernel compiler thing */

/*** kref ***/

struct kref {
    atomic_t refcount;
};

#define kref_trace(fmt, args...)    //	sys_eprintf(fmt"\n", args)

#define kref_init(kref)			_kref_init((kref), FL_STR)
static inline void
_kref_init(struct kref *kref, sstring_t caller_id)
{
    atomic_set(&(kref)->refcount, 1);
    kref_trace("%s: KREF_INIT %p", caller_id, (void *)kref);
}

#define kref_get(kref)			_kref_get((kref), FL_STR)
static inline void
_kref_get(struct kref *kref, sstring_t caller_id)
{
    int nrefs = atomic_inc_return(&(kref)->refcount);
    assert_gt(nrefs, 0);
    kref_trace("%s: KREF_GET %p increases refs to %d", caller_id, (void *)kref, nrefs);
}

#define kref_put(kref, destructor)	_kref_put((kref), (destructor), FL_STR)
static inline int
_kref_put(struct kref *kref, void (*destructor)(struct kref *), sstring_t caller_id)
{
    int nrefs = atomic_read(&(kref)->refcount);
    assert_gt(nrefs, 0);

    if (!atomic_dec_and_test(&(kref)->refcount)) {
	kref_trace("%s: KREF_PUT %p leaves %d refs remaining", caller_id, (void *)kref, nrefs-1);
	return false;
    }

    kref_trace("%s: KREF_PUT %p calls destructor", caller_id, (void *)kref);
    destructor(kref);
    return true;
}

#define kref_read(kref) (atomic_read(&(kref)->refcount))

/*** kobj ***/

struct attribute {
    const char		  * name;
    umode_t		    mode;
    void		  * owner;
};

struct kobject {
    struct kref		kref;
    struct list_head    entry;
    char	      * name;
    struct kobj_type  * ktype;
    struct kobject    * parent;
};

struct kobj_type {
    void  (*release)(struct kobject *);
    struct sysfs_ops const * sysfs_ops;
    struct attribute	 ** default_attrs;
    ssize_t (*show)(struct kobject *kobj, struct attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
};

struct kobj_attribute {
    struct attribute attr;
    ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
};

#define __ATTR(_name, _mode, _show, _store) {			    \
    .attr = { .name = __stringify(_name), .mode = _mode },	    \
    .show   = _show,						    \
    .store  = _store,						    \
}

#define _kobject_init(kobj, type)	do { record_zero(kobj);		    \
					     kref_init(&(kobj)->kref);	    \
					     (kobj)->ktype = (type);	    \
					     INIT_LIST_HEAD(&(kobj)->entry);\
					} while (0)

/* type argument was added to kobject_init() in 2.6.25 */
#define kobject_init(kobj, type...)	_kobject_init((kobj), type+0)

static inline void
kobject_release(struct kref * kref)
{
    struct kobject * kobj = container_of(kref, struct kobject, kref);
    kobj->ktype->release(kobj);
}

static inline void
kobject_put(struct kobject * kobj)
{
    if (kobj)
	kref_put(&kobj->kref, kobject_release);
}

static inline void
kobject_get(struct kobject * kobj)
{
    kref_get(&kobj->kref);
}

#define kobject_uevent(a, b)		(UMC_size_t_JUNK=E_OK)
#define KOBJ_CHANGE			IGNORED

/********** Tasks and Scheduling **********/

#define	NR_CPUS				BITS_PER_LONG	//XXX
extern unsigned int			nr_cpu_ids;

#define raw_smp_processor_id()		sched_getcpu()

static inline unsigned int
smp_processor_id(void)
{
    unsigned int id = raw_smp_processor_id();
    expect_lt(id, nr_cpu_ids);
    return id;
}

typedef struct { unsigned long bits[(NR_CPUS+BITS_PER_LONG-1) / BITS_PER_LONG]; } cpumask_t;

#define cpumask_bits(maskp)		((maskp)->bits)
#define cpumask_clear(maskp)		bitmap_zero((maskp), NR_CPUS)
#define cpumask_and(d, s1, s2)		bitmap_and((d)->bits, (s1)->bits, (s2)->bits, NR_CPUS)
#define cpumask_empty(d)		bitmap_empty((d)->bits, NR_CPUS)

#define cpumask_scnprintf(buf, bufsize, mask)	\
	    snprintf((buf), (bufsize), "<0x%016x>", mask.bits[0])

static inline int
_cpumask_test_cpu(int cpu, cpumask_t *cpumask)
{
    return _bitmap_test_bit(cpumask_bits(cpumask), cpu);
}

/* The cpumask_var_t is stored directly in the pointer, not allocated; so max 64 CPUs */
typedef cpumask_t			cpumask_var_t[1];   //XXX

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)

#define nr_cpumask_bits			nr_cpu_ids

static inline void
free_cpumask_var(cpumask_var_t mask)
{
    /* NOP */
}

static inline void
cpumask_copy(cpumask_t *dstp, const cpumask_t *srcp)
{
    bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

static inline void
cpumask_setall(cpumask_t *dstp)
{
    bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline bool
cpumask_equal(const cpumask_t *src1p, const cpumask_t *src2p)
{
    return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p), nr_cpumask_bits);
}

static inline bool
alloc_cpumask_var(cpumask_var_t *mask, gfp_t gfp)
{
    assert_static(NR_CPUS <= BITS_PER_LONG);
    return true;
}

static inline bool
zalloc_cpumask_var(cpumask_var_t *mask, gfp_t gfp)
{
    bool ok = alloc_cpumask_var(mask, gfp);
    if (ok)
	record_zero(mask);
    return ok;
}

static inline unsigned int
cpumask_next(int n, const cpumask_t *srcp)
{
    return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

static inline void
cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
    _bitmap_set_bit(cpumask_bits(dstp), cpu);
}

static inline int
cpumask_test_cpu(int cpu, cpumask_t *cpumask)
{
    return _cpumask_test_cpu(cpu, cpumask);
}

#endif

static inline bool
cpu_online(int cpun)
{
    cpu_set_t cpuset;
    int rc = sched_getaffinity(getpid(), sizeof(cpuset), &cpuset);
    if (rc) return 0;
    return _cpumask_test_cpu(cpun, (cpumask_t *)&(cpuset));
}

static inline int
num_online_cpus(void)
{
    cpu_set_t cpuset;
    //XXX maybe this is supposed to be system CPUs, not this thread's
    int rc = sched_getaffinity(getpid(), sizeof(cpuset), &cpuset);
    if (rc) return 0;
    return CPU_COUNT(&cpuset);
}

#define NUMA_NO_NODE			(-1)
#define cpu_to_node(cpu)		(0)

#define in_softirq()			false //XXX (sys_event_task_current() != NULL)
#define in_atomic()			false //XXX OK?
#define in_irq()			false	/* never in hardware interrupt */
#define in_interrupt()			(in_irq() || in_softirq())

#define need_resched()			false
#define cond_resched()			DO_NOTHING()	//XXXX ?

/*** Wait Queue -- wait (if necessary) for a condition to be true ***/

/* The actual queue itself is managed by pthreads, not visible here */
//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
typedef struct wait_queue_head {
    spinlock_t		    lock;	    /* synchronizes pcond when non-locked wait */
    pthread_cond_t	    pcond;	    /* sleep awaiting condition change */
    bool	   volatile initialized;
    bool		    is_exclusive;   /* validate XXX limitation assumption */
} wait_queue_head_t;

extern wait_queue_head_t		UMC_rcu_cb_wake;    //XXX belongs above

typedef struct wait_queue_entry	{ } wait_queue_entry_t;
#define DEFINE_WAIT(name)		struct wait_queue_entry name = { }

/* The pcond has to be initialized at runtime */
#define WAIT_QUEUE_HEAD_INIT(name)	(struct wait_queue_head){ \
					   .lock = SPINLOCK_UNLOCKED(#name), \
					   /* .pcond = PTHREAD_COND_INITIALIZER, */ \
					   .initialized = false, \
					   .is_exclusive = false}

#define DECLARE_WAIT_QUEUE_HEAD(name)	wait_queue_head_t name = WAIT_QUEUE_HEAD_INIT(name)

/* init_waitqueue_head is suitable for initializing dynamic waitqueues */
#define init_waitqueue_head(WAITQ)  /* before exposing them to the view of other threads */ \
	    do { \
		record_zero(WAITQ); \
		spin_lock_init(&(WAITQ)->lock); \
		pthread_condattr_t attr; \
		pthread_condattr_init(&attr); \
		pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
		pthread_cond_init(&(WAITQ)->pcond, &attr); \
		pthread_condattr_destroy(&attr); \
		(WAITQ)->initialized = true; \
	    } while (0)

#define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(WAITQ)  wait_queue_head_t WAITQ; \
						init_waitqueue_head(&WAITQ)

/* This is for auto-initialization of static waitqueues partially-initialized at compile-time */
#define _init_waitqueue_head(WAITQ) \
	    do { \
		spin_lock(&(WAITQ)->lock); \
		if (!(WAITQ)->initialized) { \
		    pthread_condattr_t attr; \
		    pthread_condattr_init(&attr); \
		    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
		    pthread_cond_init(&(WAITQ)->pcond, &attr); \
		    pthread_condattr_destroy(&attr); \
		    (WAITQ)->initialized = true; \
		} \
		spin_unlock(&(WAITQ)->lock); \
	    } while (0)

struct completion {
    atomic_t		    done;
    wait_queue_head_t	    wait;
};

/*** Kthread (simulated kernel threads) ***/

extern _PER_THREAD struct task_struct * current;    /* current thread */

#define TASK_COMM_LEN			16  //XXX

/* A kthread is implemented on top of a sys_thread --
 * each kthread's "current" points to that thread's instance of struct task_struct
 */
struct task_struct {
    error_t		  (*run_fn)(void *);/* kthread's work function */
    void		  * run_env;	    /* argument to run_fn */
    int			    exit_code;
    bool		    affinity_is_set;
    unsigned long  volatile signals_pending;	/* force_sig/signal_pending */
    unsigned int	    state;

    sys_thread_t	    SYS;	    /* pointer to system thread info */
    pthread_t		    pthread;

    struct completion	    started;	    /* synchronize thread start */
    struct completion	    start_release;  /* synchronize thread start */
    struct completion	    stopped;	    /* synchronize thread stop */
    wait_queue_head_t	  * waitq;	    /* for wake_up_process */

    /* kernel code compatibility */
    cpumask_t		    cpus_allowed;
    bool	   volatile should_stop;    /* kthread shutdown signalling */
    char		    comm[TASK_COMM_LEN];  /* thread name */
    pid_t		    pid;	    /* tid, actually */
    int			    flags;	    /* ignored */
    void		  * io_context;	    /* unused */
    struct mm_struct      * mm;		    /* unused */
    void		  * plug;	    //XXXX
};

#define TASK_RUNNING			0
#define TASK_INTERRUPTIBLE		1
#define TASK_UNINTERRUPTIBLE		2

#define TC_PRIO_INTERACTIVE_BULK	4
#define TC_PRIO_INTERACTIVE		6

#define kthread_should_stop()		(current->should_stop)
#define get_task_comm(buf, task)	strncpy((buf), ((task)->comm), TASK_COMM_LEN)

/* Rename kernel symbol that conflicts with library symbol */
#define sched_setscheduler UMC_sched_setscheduler

extern error_t UMC_sched_setscheduler(struct task_struct *, int policy, struct sched_param *);

#define trace_signal(fmtargs...)    //	sys_notice(fmtargs)

#define UMC_SIGNAL			SIGHUP	/* inter-thread signal */

extern int signal_pending(struct task_struct * task);

#define force_sig(signo, task)		_force_sig((signo), (task), FL_STR)
static inline void
_force_sig(unsigned long signo, struct task_struct * task, sstring_t caller_id)
{
    task->signals_pending |= 1<<signo;
    sys_notice("%s: SIGNAL %lu (0x%lx) from task %s (%d) to task %s (%d)",
		caller_id, signo, 1L<<signo, current->comm, current->pid,
		task->comm, task->pid);
    error_t err = pthread_kill(task->pthread, UMC_SIGNAL);
    if (err != E_OK)
	sys_warning("%s: FAILED TO SIGNAL %lu (0x%lx) from task %s (%d) to task %s (%d) err=%d",
		    caller_id, signo, 1L<<signo, current->comm, current->pid,
		    task->comm, task->pid, err);
}

#define flush_signals(task)		_flush_signals((task), FL_STR)
static inline void
_flush_signals(struct task_struct * task, sstring_t caller_id)
{
    if (current == task)
	sys_notice("%s: task %s (%d) FLUSH SIGNALS (0x%lx)", caller_id,
	    current->comm, current->pid, task->signals_pending);
    else
	sys_notice("%s: task %s (%d) FLUSH SIGNALS (0x%lx) of task %s (%d)", caller_id,
	    current->comm, current->pid, task->signals_pending, task->comm, task->pid);

    task->signals_pending = 0;
}

#define UMC_current_alloc()	((struct task_struct *)vzalloc(sizeof(struct task_struct)))

#define UMC_current_init(task, _SYS, _FN, _ENV, _COMM) \
	    ({ \
		struct task_struct * __t = (task); \
		__t->SYS = (_SYS); \
		__t->run_fn = (_FN); \
		__t->run_env = (_ENV); \
		strncpy(__t->comm, (_COMM), sizeof(__t->comm)); \
		trace("UMC_current_init(%p) from %s comm=%s", __t, FL_STR, __t->comm); \
		__t; \
	    })

#define UMC_current_set(task) \
	    do { \
		struct task_struct * _t = (task); \
		if (_t != NULL) { \
		    assert_eq(current, NULL); \
		    _t->pid = gettid(); \
		    _t->pthread = pthread_self(); \
		} else { \
		    assert(current != NULL); \
		} \
		current = _t; \
	    } while (0)

#define UMC_current_free(task) \
	    do { \
		struct task_struct * _t = (task); \
		trace("UMC_current_free(%p) from %s", _t, FL_STR); \
		vfree(_t); \
	    } while (0)

/*** Waiting ***/

/* The WAITQ_CHECK_INTERVAL is a hack to allow checking for unwoken events like signals.  Note
 * that pthread_cond_timedwait() does not return EINTR, so signals do not interrupt it.  We wake
 * up to recheck the COND each time interval, even if no wakeup has been sent; so that interval
 * is the maximum delay between an unwoken event and the thread noticing it.
 * XXX fix so that we can wake them up
 */
#define WAITQ_CHECK_INTERVAL	sys_time_delta_of_ms(150)   /* signal check interval */

/* Await a wakeup for a limited time.
 * Called to check if done waiting and/or wait when COND has evaluated false.
 * Return true if full wait is complete, false if full wait is not complete.
 *
 * If INNERLOCKP != NULL, lock acquisition order is LOCKP, INNERLOCKP;
 * The pthread_cond_timedwait() call drops the outer (or solitary) LOCKP.
 */
static inline bool
_UMC_wait_locked(wait_queue_head_t * wq,
		 spinlock_t * lockp, spinlock_t * innerlockp, sys_time_t t_end)
{
    sys_time_t now = sys_time_now();
    sys_time_t next_check;

    spin_lock_assert_holding(lockp);
    if (innerlockp)
	spin_lock_assert_holding(innerlockp);
    // expect_a(t_end + sys_time_delta_of_ms(100), now);	//XXX
    expect_ne(current->state, TASK_RUNNING);
    if (unlikely(!wq->initialized))
	_init_waitqueue_head(wq);

    if (time_after_eq(now, t_end))
	return true;	/* wait ends due to timeout */

    if (current->state != TASK_UNINTERRUPTIBLE && signal_pending(current))
	return true;	/* wait ends due to signal */

    if (time_after(now + WAITQ_CHECK_INTERVAL, t_end))
	next_check = t_end;
    else
	next_check = now + WAITQ_CHECK_INTERVAL;

    struct timespec const ts_end = {
		.tv_sec = sys_time_delta_to_sec(next_check),
		.tv_nsec = sys_time_delta_mod_sec(next_check)
    };

    if (innerlockp)
	spin_unlock(innerlockp);
    SPINLOCK_DISCLAIM(lockp);	    /* cond_wait drops LOCK */

    pthread_cond_timedwait(&wq->pcond, &(lockp)->plock, &ts_end);

    SPINLOCK_CLAIM(lockp);	    /* cond_wait reacquires LOCK */
    if (innerlockp)
	spin_lock(innerlockp);

    return false;	/* wait still in progress */
}

/* Return sys_time remaining */
static inline sys_time_t
schedule_timeout_abs(sys_time_t t_end)
{
    spin_lock(&current->waitq->lock);
    if (current->state != TASK_RUNNING && current->waitq)
	_UMC_wait_locked(current->waitq, &current->waitq->lock, NULL, t_end);
    spin_unlock(&current->waitq->lock);
    sys_time_t now = sys_time_now();
    return time_after_eq(now, t_end) ? 0 : (t_end - now);
}

/* Return jiffies remaining */
#define schedule_timeout(jdelta) ({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    jiffies_of_sys_time(schedule_timeout_abs(t_end)); \
})

#define schedule() schedule_timeout_abs(SYS_TIME_MAX)

#define prepare_to_wait(WQ, W, TSTATE) do { \
    current->waitq = (WQ); \
    current->state = (TSTATE); \
    _USE(W); \
} while (0)

#define finish_wait(WQ, W) do { \
    current->waitq = NULL; \
    current->state = TASK_RUNNING; \
} while (0)

/* Returns the number of jiffies remaining */
#define schedule_timeout_interruptible(jdelta) ({ \
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(sti_wait); \
	prepare_to_wait(&sti_wait, 0, TASK_INTERRUPTIBLE); \
	int ret = schedule_timeout(jdelta); \
	finish_wait(&sti_wait, 0); \
	ret; \
})

#define schedule_timeout_uninterruptible(jdelta) ({ \
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(stu_wait); \
	prepare_to_wait(&stu_wait, 0, TASK_UNINTERRUPTIBLE); \
	int ret = schedule_timeout(jdelta); \
	finish_wait(&stu_wait, 0); \
	ret; \
})

/* With all of these wait macros it is important that COND evaluate TRUE at most once! */

/* Returns true when condition is seen to be met, or false after timeout or signal */
#define UMC_wait_locked(WAITQ, COND, LOCKP, INNERLOCKP, t_end) \
({ \
    bool UMC_wl_cond_met; \
    while (!(UMC_wl_cond_met = !!(COND))) { \
	if (_UMC_wait_locked(&(WAITQ), (LOCKP), (INNERLOCKP), t_end)) \
	    break; /* timeout or signal */ \
    } \
    UMC_wl_cond_met ? true : !!(COND); /* return */ \
})

/* Common internal helper for exclusive wakeups */
#define _wait_event_locked2(WAITQ, COND, LOCKP, INNERLOCKP) \
do { \
    (WAITQ).is_exclusive = true; \
    prepare_to_wait(&(WAITQ), 0, TASK_INTERRUPTIBLE); \
    UMC_wait_locked((WAITQ), (COND), (LOCKP), (INNERLOCKP), SYS_TIME_MAX); \
    finish_wait((WAITQ), 0); \
} while (0)

/* Caution: these "wait_event" macros use unnatural pass-by-name semantics */
/* XXX Limitation: locked waits are always exclusive, non-locked always non-exclusive */

/* Wait Event with exclusive wakeup, NO timeout, interruptible, and spinlock */
#define wait_event_locked(WAITQ, COND, lock_type, LOCK) \
		_wait_event_locked2((WAITQ), (COND), &(LOCK), NULL)

/* Wait Event with exclusive wakeup, NO timeout, interruptible, and TWO spinlocks --
 * Lock acquisition order is LOCK, INNERLOCK
 */
#define wait_event_locked2(WAITQ, COND, LOCK, INNERLOCK) \
		_wait_event_locked2((WAITQ), (COND), &(LOCK), &(INNERLOCK))

//XXX Testing COND outside the lock because otherwise the lock is already held by the thread
//    when DRBD recurses back into another wait from inside the COND of the first wait.

/* Common internal helper for non-exclusive wakeups --
 * returns true when condition is seen to be met, or false after timeout or signal.
 */
#define UMC_wait_unlocked(WAITQ, COND, LOCKP, INNERLOCKP, t_end) \
({ \
    bool UMC_wl_cond_met; \
    while (!(UMC_wl_cond_met = !!(COND))) { \
	spin_lock(&(WAITQ).lock); \
	bool _done = _UMC_wait_locked(&(WAITQ), (LOCKP), (INNERLOCKP), t_end); \
	spin_unlock(&(WAITQ).lock); \
	if (_done) \
	    break; /* timeout or signal */ \
    } \
    UMC_wl_cond_met ? true : !!(COND); /* return */ \
})

/* Common internal helper for non-exclusive wakeups --
 * Returns true if condition was seen to be met, false otherwise
 */
#define wait_event_timeout_abs(WAITQ, COND, T_STATE, t_end) \
({ \
    expect_eq((WAITQ).is_exclusive, false, "Mixed waitq exclusivity"); \
    prepare_to_wait(&(WAITQ), 0, (T_STATE)); \
    bool weta_cond_met = UMC_wait_unlocked((WAITQ), (COND), &(WAITQ).lock, NULL, (t_end)); \
    finish_wait((WAITQ), 0); \
    weta_cond_met; \
})

/* Non-exclusive wakeup with NO timeout, uninterruptible */
#define wait_event(WAITQ, COND) \
({ \
    bool we_cond_met = \
	    wait_event_timeout_abs((WAITQ), (COND), TASK_UNINTERRUPTIBLE, SYS_TIME_MAX); \
    expect_eq(we_cond_met, true); \
})

/* Non-exclusive wakeup WITH timeout, uninterruptible --
 * Returns ticks remaining (minimum one) if the condition was seen to be met.
 * Returns zero if it times out.
 */
#define wait_event_timeout(WAITQ, COND, jdelta) \
({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    bool wet_cond_met = wait_event_timeout_abs((WAITQ), (COND), TASK_UNINTERRUPTIBLE, t_end); \
    sys_time_t now = sys_time_now(); \
    !wet_cond_met ? 0 : time_after_eq(now, t_end) ? 1 : \
		    jiffies_of_sys_time(t_end - now) ?: 1; \
})

/* Non-exclusive wakeup with NO timeout, interruptible --
 * Returns zero if the condition was seen to be met, otherwise -ERESTARTSYS
 */
#define wait_event_interruptible(WAITQ, COND) \
({ \
    bool wei_cond_met = \
	    wait_event_timeout_abs((WAITQ), (COND), TASK_INTERRUPTIBLE, SYS_TIME_MAX); \
    expect_eq(wei_cond_met || signal_pending(current), true); \
    wei_cond_met ? 0 : -ERESTARTSYS; \
})

/* Non-exclusive wakeup WITH timeout, interruptible --
 * Returns ticks remaining (minimum one) if the condition was seen to be met.
 * Returns -ERESTARTSYS if signalled, or zero if it times out.
 */
#define wait_event_interruptible_timeout(WAITQ, COND, jdelta) \
({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    bool weit_cond_met = wait_event_timeout_abs((WAITQ), (COND), TASK_INTERRUPTIBLE, t_end); \
    sys_time_t now = sys_time_now(); \
    !weit_cond_met ? (signal_pending(current) ? -ERESTARTSYS : 0) \
	      : (time_after_eq(now, t_end) ? 1 : jiffies_of_sys_time(t_end - now) ?: 1); \
})

/* First change the condition being waited on, then call wake_up*() --
 * These may be called with or without holding the associated lock;
 * if called without, the caller is responsible for handling the races.
 */
#define wake_up_one(WAITQ) \
	    do { \
		/* if (unlikely(!(WAITQ)->initialized)) sys_breakpoint(); */ \
		pthread_cond_signal(&(WAITQ)->pcond); \
	    } while (0)

#define wake_up_all(WAITQ) \
	    do { \
		/* if (unlikely(!(WAITQ)->initialized)) sys_breakpoint(); */ \
		pthread_cond_broadcast(&(WAITQ)->pcond); \
	    } while (0)

//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
#define wake_up(WAITQ) \
	    do { \
		if ((WAITQ)->is_exclusive) \
		    wake_up_one(WAITQ); \
		else \
		    wake_up_all(WAITQ); \
	    } while (0)

/*** Completion ***/

#define COMPLETION_INIT(name)	{	.wait = WAIT_QUEUE_HEAD_INIT((name).wait), \
					.done = { 0 } \
				}

#define DECLARE_COMPLETION(name)	struct completion name = COMPLETION_INIT(name)


#define init_completion(c)		do { init_waitqueue_head(&(c)->wait); \
					     atomic_set(&(c)->done, 0); \
					} while (0)

#define COMPLETION_INITIALIZER_ONSTACK(c)  COMPLETION_INIT(c)

#define DECLARE_COMPLETION_ONSTACK(name) struct completion name; \
					 init_completion(&name)

#define complete(c) \
	    do { atomic_inc(&(c)->done); wake_up(&(c)->wait); } while (0)

#define complete_all(c) \
	    do { atomic_set(&(c)->done, 1ul<<30); wake_up_all(&(c)->wait); } while (0)

/* Returns ticks remaining (min 1) if the completion occurred, 0 if it timed out */
static inline int
wait_for_completion_timeout(struct completion * c, uint32_t jdelta)
{
    bool cond_met;
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta);
    while (atomic_dec_return(&c->done) < 0) {
	/* Overdraft -- give it back */
	atomic_inc(&c->done);
	cond_met = wait_event_timeout_abs(c->wait, atomic_read(&c->done) > 0,
						TASK_UNINTERRUPTIBLE, t_end);
	if (!cond_met)
	    return 0;	/* timed out */
    }
    sys_time_t now = sys_time_now(); \
    return time_after_eq(now, t_end) ? 1 : \
		    jiffies_of_sys_time(t_end - now) ?: 1; \
}

static inline void
wait_for_completion(struct completion * c)
{
    while (atomic_dec_return(&c->done) < 0) {
	/* Overdraft -- give it back */
	atomic_inc(&c->done);
	wait_event(c->wait, atomic_read(&c->done) > 0);
    }
}

/* Wake up a specific task --
 * Each newly-created task needs a call here to get started.
 * Limitation: only implemented for task startup
 */
#define wake_up_process(task)	_wake_up_process(task, FL_STR)
static inline void
_wake_up_process(struct task_struct * task, string_t whence)
{
    /* Let a newly-created thread get going */
    complete(&task->start_release);
    pr_debug("%s: thread %s (%p, %u) WAKES UP thread %s (%p) task %s (%p)\n",
		whence, sys_thread_name(sys_thread), sys_thread, current->pid,
		sys_thread_name(task->SYS), task->SYS, task->comm, task);
}

extern error_t UMC_kthread_fn(void * v_task);    /* start function for a new kthread */

/* Create and initialize a kthread structure -- the pthread is not started yet */
#define kthread_create(fn, env, fmtargs...) \
	    _kthread_create((fn), (env), sys_sprintf(fmtargs), FL_STR)
static inline struct task_struct *
_kthread_create(error_t (*fn)(void * env), void * env, string_t name, sstring_t caller_id)
{
    struct task_struct * task = UMC_current_alloc();
    init_completion(&task->started);
    init_completion(&task->start_release);
    init_completion(&task->stopped);

    sys_thread_t thread = sys_thread_alloc(UMC_kthread_fn, task, vstrdup(name));
    mem_buf_allocator_set(thread, caller_id);

    /* name string is copied into comm[] in the task_struct */
    UMC_current_init(task, thread, fn, env, name);
    kfree(name);

    task->SYS->cpu_mask = current->SYS->cpu_mask;
    task->SYS->nice = nice(0);
    task->cpus_allowed = current->cpus_allowed;	    //XXX Right?

    pr_debug("Thread %s (%p, %u) creates kthread %s (%p) task %s (%p)\n",
	     sys_thread_name(sys_thread), sys_thread, current->pid,
	     sys_thread_name(thread), thread,
	     task->comm, task);

    error_t const err = sys_thread_start(task->SYS);
    if (err != E_OK) {
	/* Failed to start */
	sys_thread_free(task->SYS);
	UMC_current_free(task);
	return ERR_PTR(err);
    }

    /* Wait for new thread to be ready */
    wait_for_completion(&task->started);

    return task;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#define kthread_create_on_node(fn, env, node, fmtargs...) \
	    _kthread_create((fn), (env), sys_sprintf(fmtargs))
#endif

/* Create and start a kthread */
#define kthread_run(fn, env, fmtargs...) UMC_kthread_run((fn), (env), sys_sprintf(fmtargs), FL_STR)
extern struct task_struct * UMC_kthread_run(error_t (*fn)(void * env), void * env,
				    string_t name, sstring_t caller_id);

extern struct task_struct * UMC_run_shutdown(error_t (*fn)(void * env), void * env);

extern error_t kthread_stop(struct task_struct *);

#define task_pid_vnr(task)		((task)->pid)
#define task_pid_nr(task)		((task)->pid)

/* This can be called on behalf of a new task before the pthread has been created */
#define set_cpus_allowed(task, mask) ( \
	    (task)->cpus_allowed = (mask), \
	    (task)->affinity_is_set = true, \
	    (task)->pid \
		? UMC_kernelize(sched_setaffinity((task)->pid, (int)sizeof(mask), \
						  (cpu_set_t *)&((task)->cpus_allowed))) \
		: E_OK		     )

#define tsk_cpus_allowed(task)		(&(task)->cpus_allowed)

#define set_user_nice(task, niceness)	//XXX setpriority(PRIO_PROCESS, (task)->pid, (niceness))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)

#define for_each_cpu(cpu, mask)				    \
	    for ((cpu) = cpumask_next(-1, (mask));	    \
		    (cpu) = cpumask_next((cpu), (mask)),    \
		    (cpu) < nr_cpu_ids;)

#define for_each_online_cpu(cpu)	for_each_cpu(cpu, tsk_cpus_allowed(current))	//XXX

#define set_cpus_allowed_ptr(task, maskp) set_cpus_allowed((task), *(maskp))
#endif

/*** Tasklet ***/

// #define UMC_TASKLETS

struct tasklet_struct {
#ifdef UMC_TASKLETS
    spinlock_t			    lock;
    pthread_cond_t		    pcond;
    struct task_struct		  * owner;
    void			  (*fn)(long);
    long			    arg;
    bool		   volatile is_idle;
    bool		   volatile want_run;
    sstring_t			    name;
#endif
};

extern error_t UMC_tasklet_thr(void * v_tasklet);

#ifndef UMC_TASKLETS
#define tasklet_init(x, y, z)		DO_NOTHING()
#define tasklet_schedule(tasklet)	UMC_STUB(tasklet)
#define tasklet_kill(tasklet)		UMC_STUB(tasklet)
#else

#define tasklet_init(tasklet, fn, arg)	    __tasklet_init((tasklet), (fn), (arg), #fn)
static inline void
__tasklet_init(struct tasklet_struct * tasklet, void (*fn)(long), long arg, sstring_t name)
{
    tasklet->name = name;
    spin_lock_init(&tasklet->lock);
    tasklet->fn = fn;
    tasklet->arg = arg;
    tasklet->is_idle = true;
    pthread_cond_init(&tasklet->pcond, NULL);

    spin_lock(&tasklet->lock);
    tasklet->owner = kthread_run(UMC_tasklet_thr, tasklet, "%s", name);
    mem_buf_allocator_set(tasklet->owner, name);
    spin_unlock(&tasklet->lock);
}

static inline void
tasklet_schedule(struct tasklet_struct * tasklet)
{
    spin_lock(&tasklet->lock);
    tasklet->want_run = true;
    if (tasklet->is_idle) {
	tasklet->is_idle = false;
	pthread_cond_signal(&tasklet->pcond);
    }
    spin_unlock(&tasklet->lock);
}

static inline void
tasklet_kill(struct tasklet_struct * tasklet)
{
    kthread_stop(tasklet->owner);
    pthread_cond_destroy(&tasklet->pcond);
    record_zero(tasklet);
}
#endif

/*** Event thread (used for timers and "softirq" asynchronous notifications) ***/

extern struct _irqthread * UMC_irqthread;   /* delivers "softirq" callbacks */

struct _irqthread {
    struct task_struct    * current;
    sys_event_task_t	    event_task;
    sys_thread_t	    SYS;	    /* pointer to system thread info */
    struct completion	    started;	    /* synchronize thread start */
    struct completion	    stopped;	    /* synchronize thread stop */
};

extern error_t UMC_irqthread_fn(void * v_irqthread);

#define irqthread_alloc(fmtargs...) _irqthread_alloc(sys_sprintf(fmtargs))

static inline struct _irqthread *
_irqthread_alloc(string_t name)
{
    pr_debug("Thread %s (%u) creates irqthread %s\n", current->comm, current->pid, name);

    struct _irqthread * ret = record_alloc(ret);
    init_completion(&ret->started);
    init_completion(&ret->stopped);

    ret->SYS = sys_thread_alloc(UMC_irqthread_fn, ret, vstrdup(name));
    ret->SYS->cpu_mask = current->SYS->cpu_mask;
    ret->SYS->nice = nice(0) - 5;	//XXX TUNE

    /* The thread will deliver into "kernel" code expecting a "current" to be set */
    ret->current = UMC_current_alloc();

    /* name string is copied into comm[] in the task_struct */
    UMC_current_init(ret->current, ret->SYS, (void *)UMC_irqthread_fn, ret, name);
    kfree(name);

    struct sys_event_task_cfg cfg = {
	.max_polls = SYS_ETASK_MAX_POLLS,
	.max_steps = SYS_ETASK_MAX_STEPS,
    };

    ret->event_task = sys_event_task_alloc(&cfg);
    assert(ret->event_task);

    return ret;
}

static inline error_t
irqthread_start(struct _irqthread * irqthread)
{
    error_t const err = sys_thread_start(irqthread->SYS);
    if (err == E_OK) {
	/* Wait for new thread to be ready */
	wait_for_completion(&irqthread->started);
    }
    return err;
}

/* Tells the irqthread to stop and waits for it to exit */
static inline void
irqthread_stop(struct _irqthread * irqthread)
{
    verify(irqthread->SYS != sys_thread_current());
    sys_event_task_stop(irqthread->event_task);
    wait_for_completion(&irqthread->stopped);
}

static inline void
irqthread_destroy(struct _irqthread * irqthread)
{
    sys_event_task_free(irqthread->event_task);
    irqthread->event_task = (void *)MEM_ZAP_64;
    sys_thread_free(irqthread->SYS);
    irqthread->SYS = (void *)MEM_ZAP_64;
    UMC_current_free(irqthread->current);
    irqthread->current = (void *)MEM_ZAP_64;
    record_free(irqthread);
}

#define irqthread_run(fmtargs...)	_irqthread_run(sys_sprintf(fmtargs))

static inline struct _irqthread *
_irqthread_run(string_t name)
{
    struct _irqthread * irqthread = _irqthread_alloc(name);

    error_t err = irqthread_start(irqthread);
    if (err != E_OK) {
	irqthread_destroy(irqthread);
	return ERR_PTR(err);
    }

    return irqthread;
}

/*** Timer ***/

#define msleep(ms)			usleep((ms) * 1000)
#define jsleep(jiffies)			msleep(jiffies_to_msecs(jiffies))

extern void UMC_alarm_handler(void * v_timer, uint64_t const now, error_t);

struct timer_list {
    void		  (*function)(uintptr_t);   /* kernel-code handler */
    uintptr_t		    data;		    /* kernel-code handler arg */
    uint64_t		    expires;		    /* expiration "jiffy" time */
    sys_alarm_entry_t	    alarm;		    /* non-NULL when alarm pending (ticking) */
};

#define init_timer(timer)		record_zero(timer)
#define timer_pending(timer)		((timer)->alarm != NULL)
#define setup_timer(_timer, _fn, _data)	do { init_timer(_timer);		    \
					     (_timer)->function = (_fn);	    \
					     (_timer)->data = (uintptr_t)(_data);   \
					} while (0)

/* Callable from any thread to cancel a timer -- return true if timer was ticking */
static inline int
del_timer_sync(struct timer_list * timer)
{
    sys_alarm_entry_t alarm = timer->alarm;
    if (unlikely(alarm == NULL)) return false;	    /* not pending */

    /* sys_alarm_cancel() cancels if possible; otherwise synchronizes with delivery to
     * guarantee the event task thread is not (any longer) executing the handler (for
     * the alarm we tried to cancel) at the time sys_alarm_cancel() returns to us here.
     */
    error_t const err = sys_alarm_cancel(UMC_irqthread->event_task, alarm);

    /* The alarm now either has been cancelled, or its delivery callback has completed
     * (in either case the alarm entry itself has been freed)
     */
    if (likely(err == E_OK)) {
	timer->alarm = NULL;		/* Cancelled the alarm */
    } else {
	assert_eq(err, EINVAL);		/* alarm entry not found on list */
//XXXXX	expect_eq(timer->alarm, NULL);	/* UMC_alarm_handler cleared this */
	//XXX need to fix
	timer->alarm = NULL;		//XXX timer went off before timer->alarm assigned
    }

    return true;
}

#define del_timer(timer)		del_timer_sync(timer)

#define add_timer(timer)		_add_timer((timer), FL_STR)
static inline void
_add_timer(struct timer_list * timer, sstring_t whence)
{
    assert_eq(timer->alarm, NULL);
    assert(timer->function);
    expect_a(timer->expires, 0, "Adding timer with expiration at time zero");
    //XXXXX BUG: alarm can go off before timer->alarm gets set!
    timer->alarm = sys_alarm_set(UMC_irqthread->event_task,
				 UMC_alarm_handler, timer,
				 jiffies_to_sys_time(timer->expires), whence);
}

static inline void
mod_timer(struct timer_list * timer, uint64_t expire_j)
{
    del_timer_sync(timer);
    timer->expires = expire_j;
    add_timer(timer);
}

#define mod_timer_pending(timer, expire) mod_timer(timer, expire)

/*** Work Queue ***/

/* Has to be embedded in some other state, having no env pointer */
struct work_struct {
    struct list_head		    entry;
    void			  (*fn)(struct work_struct *);
    struct workqueue_struct	  * wq;		    /* for cancel */
    void			  * lockdep_map;    /* unused */
};

#define INIT_WORK(WORK, _fn)		do { INIT_LIST_HEAD(&(WORK)->entry); \
					     (WORK)->fn = (_fn); \
					} while (0)

struct delayed_work {
    struct timer_list	    timer;
    struct work_struct	    work;   /* consumer expects this substructure */
};

#define INIT_DELAYED_WORK(DWORK, _fn)	do { init_timer(&(DWORK)->timer); \
					     INIT_WORK(&(DWORK)->work, (_fn)); \
					} while (0)

extern void UMC_delayed_work_process(uintptr_t u_dwork);

#define schedule_delayed_work(DWORK, dt_j) \
	    do { setup_timer(&(DWORK)->timer, UMC_delayed_work_process, (DWORK)); \
		 mod_timer(&(DWORK)->timer, sys_time_now() + jiffies_to_sys_time(dt_j)); \
	    } while (0)

#define cancel_delayed_work_sync(DWORK)	del_timer_sync(&(DWORK)->timer)
#define cancel_delayed_work(DWORK)	cancel_delayed_work_sync(DWORK)

struct workqueue_struct {
    struct list_head		    list;
    spinlock_t			    lock;
    struct task_struct		  * owner;
    struct wait_queue_head	    wake;
    struct wait_queue_head	    flushed;
    bool		   volatile is_idle;
    atomic_t		   volatile is_flushing;
    char			    name[64];
};

extern error_t UMC_work_queue_thr(void * v_workq);

static inline struct workqueue_struct *
create_workqueue(sstring_t name)
{
    struct workqueue_struct * workq = record_alloc(workq);
    INIT_LIST_HEAD(&workq->list);
    spin_lock_init(&workq->lock);
    init_waitqueue_head(&workq->wake);
    init_waitqueue_head(&workq->flushed);
    strncpy(workq->name, name, sizeof(workq->name)-3);

    spin_lock(&workq->lock);	/* synchronize with owner assertion in UMC_work_queue_thr */

    workq->owner = kthread_run(UMC_work_queue_thr, workq, "%s", name);
    mem_buf_allocator_set(workq->owner, name);

    spin_unlock(&workq->lock);

    return workq;
}

#define create_singlethread_workqueue(name)	    create_workqueue(name)

static inline void
destroy_workqueue(struct workqueue_struct * workq)
{
    kthread_stop(workq->owner);
    record_free(workq);
}

#define queue_work(WORKQ, WORK)	\
	    ( !list_empty_careful(&(WORK)->entry) \
		? false	/* already on list */ \
		: ({ bool _do_wake = false; \
		     (WORK)->wq = (WORKQ); \
		     spin_lock(&(WORKQ)->lock); \
		     {   list_add_tail(&(WORK)->entry, &(WORKQ)->list); \
			 if (unlikely((WORKQ)->is_idle)) \
			    _do_wake = true; \
		     } \
		     spin_unlock(&(WORKQ)->lock); \
		     if (unlikely(_do_wake)) \
			wake_up(&(WORKQ)->wake); \
		     true;  /* added to list */ }) \
	    )

#define flush_workqueue(WORKQ) \
	    do { spin_lock(&(WORKQ)->lock); \
		 {   atomic_inc(&(WORKQ)->is_flushing); \
		     wake_up(&(WORKQ)->wake); \
		     wait_event_locked((WORKQ)->flushed, \
			   list_empty_careful(_VOLATIZE(&(WORKQ)->list)), lock, (WORKQ)->lock); \
		 } \
		 spin_unlock(&(WORKQ)->lock); \
	    } while (0);

/* Global general-use work queue */
extern struct workqueue_struct * UMC_workq;
#define schedule_work(WORK)		queue_work(UMC_workq, (WORK))
#define flush_scheduled_work()		flush_workqueue(UMC_workq)

//XXX could do better than this
#define flush_work(WORK) do { \
    if (!list_empty(&(WORK)->entry)) \
	flush_workqueue((WORK)->wq) \
} while (0)

//XXXX could do much better than this (cancel_work_sync)
#define cancel_work_sync(WORK) do { \
    if (!list_empty(&(WORK)->entry)) \
	flush_workqueue((WORK)->wq) \
} while(0)

/********** I/O **********/

/*** Page Structure ***/

struct bio;

struct page {
    struct list_head			UMC_page_list;
    struct list_head			lru;	/* field overloaded by drbd! */
    struct kref				kref;
    mutex_t				lock;
    unsigned short			order;
    long				private;
    struct address_space	      * mapping;    /* keep NULL */
    void			      * vaddr;
};

extern struct list_head UMC_pagelist;
extern spinlock_t UMC_pagelist_lock;

#define page_address(page)		((page)->vaddr)
#define page_count(page)		kref_read(&(page)->kref)
#define page_private(page)		((page)->private)
#define set_page_private(page, v)	((page)->private = (v))

#define PFN_UP(len)			(((len) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define page_to_pfn(page)		((uintptr_t)page_address(page) >> PAGE_SHIFT)

#define vmalloc_to_page(addr)		virt_to_page(addr)
#define offset_in_page(addr)		virt_to_page_ofs(addr)

#define virt_to_page_ofs(addr)		((size_t)((uintptr_t)(addr) & ~PAGE_MASK))

/* Ugh.  Search down the page list to find the one containing the specified addr */
//XXXX PERF virt_to_page needs a faster lookup
static inline struct page *
virt_to_page(const void * addr)
{
    struct page * ret = NULL;
    struct page * page;
    spin_lock(&UMC_pagelist_lock);
    list_for_each_entry(page, &UMC_pagelist, UMC_page_list) {
	void * page_addr = page_address(page);
	if (page_addr <= addr && addr < page_addr + (1 << page->order)) {
	    ret = page;
	    break;
	}
    }
    spin_unlock(&UMC_pagelist_lock);
    expect_ne(ret, NULL, "could not find address %p in page list", addr);

    if (!ret)
	sys_breakpoint();
    return ret;
}

static inline void
_free_page_struct(struct kref * kref)
{
    struct page * page = container_of(kref, struct page, kref);
    spin_lock(&UMC_pagelist_lock);
    list_del(&page->UMC_page_list);
    spin_unlock(&UMC_pagelist_lock);
    mutex_destroy(&page->lock);
    pages_free(page_address(page), page->order);
    record_free(page);
}

static inline int
put_page(struct page * page)
{
    return kref_put(&page->kref, _free_page_struct);
}

#define __free_page(page)		__free_pages((page), 0)
#define __free_pages(page, ord)		({ expect_eq((ord), (page)->order); \
					   put_page(page); })

//XXX I think this is supposed to allocate a single "page" of specified size,
//    (as opposed to a chain of pages each of PAGE_SIZE), but uncertain.
//    But for now it looks like we only get called with order zero, that'll work.
#define alloc_pages(gfp, order)		_alloc_pages((gfp), (order), FL_STR)
static inline struct page *
_alloc_pages(gfp_t gfp, unsigned int order, sstring_t caller_id)
{
    //XXXX Use a kmem_cache for the page structure
    struct page * page = record_alloc(page);
    mem_buf_allocator_set(page, caller_id);

    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = order;

    expect_eq(order, 0, "usermode_lib.h: Check semantics for alloc_pages()");
    page_address(page) = __get_free_pages(gfp, order);
    mem_buf_allocator_set(page_address(page), caller_id);

    spin_lock(&UMC_pagelist_lock);
    list_add(&page->UMC_page_list, &UMC_pagelist);
    spin_unlock(&UMC_pagelist_lock);

    return page;
}

#define page_cache_async_readahead(map, ra, filp, page, x, y)	DO_NOTHING()
#define page_cache_sync_readahead(map, ra, filp, index, x)	DO_NOTHING()
#define mapping_writably_mapped(map)	false	/* no address aliasing */

#define flush_dcache_page(page)		DO_NOTHING()		//XXXX

#define alloc_page(gfp)			alloc_pages(gfp, 0)
#define clear_page(addr)		memset((addr), 0, PAGE_SIZE)
#define copy_highpage(to, from)		copy_page(page_address(to), page_address(from))

#define mark_page_accessed(page)	DO_NOTHING()
#define lock_page_killable(page)	({ mutex_lock(&(page)->lock); E_OK; })
#define trylock_page(page)		mutex_trylock(&(page)->lock)
#define unlock_page(page)		mutex_unlock(&(page)->lock)

#define ClearPageError(page)		DO_NOTHING()
#define PageReadahead(page)		E_OK
#define PageSlab(page)			false
#define PageUptodate(page)		true		//XXX

#define kmap(page)			(page_address(page))
#define kmap_atomic(page, km_type)	(page_address(page))
#define kunmap(page)			DO_NOTHING()
#define kunmap_atomic(page, obsolete)	DO_NOTHING()

#define KM_BIO_SRC_IRQ			IGNORED
#define KM_BIO_DST_IRQ			IGNORED
#define KM_SOFTIRQ0			IGNORED
#define KM_SOFTIRQ1			IGNORED
#define KM_USER0			IGNORED
#define KM_USER1			IGNORED
#define KM_IRQ1				IGNORED

/* Return binary order of magnitude of val, where PAGE_SIZE is (the high-end of) order zero */
static inline int
get_order(unsigned long val)
{
    unsigned long scaled_val = (val - 1) / PAGE_SIZE;
    return 1 + ilog2(scaled_val);
}

extern struct page zero_page;
#define ZERO_PAGE(vaddr)		(expect_eq((vaddr), 0), &zero_page)

/* page_pool uses a pair of pools for the struct pages and the data pages */

static inline void *
_page_pool_alloc(gfp_t gfp, void * mp_v)
{
    mempool_t * mp = mp_v;
    struct page * page = kmem_cache_alloc(mp->pool_data3, gfp);
    expect_eq(mp->private, 0);	/* only order zero for now */
    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = mp->private;
    page_address(page) = kmem_cache_alloc(mp->pool_data2, gfp);

    spin_lock(&UMC_pagelist_lock);
    list_add(&page->UMC_page_list, &UMC_pagelist);
    spin_unlock(&UMC_pagelist_lock);
    return page;
}

static inline void
_page_pool_free(void * page_v, void * mp_v)
{
    mempool_t * mp = mp_v;
    struct page * page = page_v;
    spin_lock(&UMC_pagelist_lock);
    list_del(&page->UMC_page_list);
    spin_unlock(&UMC_pagelist_lock);

    mutex_destroy(&page->lock);
    kmem_cache_free(mp->pool_data2, page_address(page));
    kmem_cache_free(mp->pool_data3, page);
}

static inline void
_page_pool_destroy(mempool_t * mp)
{
    kmem_cache_destroy((mp)->pool_data3);
    kmem_cache_destroy((mp)->pool_data2);
    record_free(mp);
}

#define mempool_create_page_pool(min_nr, order) \
					_mempool_create_page_pool((min_nr), (order), FL_STR)

//XXXX use mmap for pages
static inline mempool_t *
_mempool_create_page_pool(int min_nr, int order, sstring_t caller_id)
{
    struct kmem_cache * kcache = kmem_cache_create("page_pool",
					  sizeof(struct page), __CACHE_LINE_BYTES,
					  IGNORED, IGNORED);
    mempool_t * mp = mempool_create(min_nr, _page_pool_alloc, _page_pool_free, (void *)kcache);
    mp->pool_data3 = mp->pool_data;
    mp->pool_data = mp;	/* pass the mempool to the alloc/free functions */
    mp->pool_data2 = kmem_cache_create("kmalloc_pool", PAGE_SIZE<<order,
					KMEM_CACHE_ALIGN(PAGE_SIZE<<order), IGNORED, IGNORED);
    mp->private = order;
    mp->destroy_fn = _page_pool_destroy;
    mem_buf_allocator_set(mp, caller_id);
    return mp;
}

/*** Request Queue ***/

typedef int				(congested_fn)(void *, int);

struct backing_dev_info {
    struct device		      * dev;
    char			      * name;
    unsigned long			ra_pages;	    /* keep zero */
    void			      * congested_data;	    /* unused */
    congested_fn		      * congested_fn;	    /* unused */
};

//XXX "congested" unimplemented
#define BDI_async_congested		0
#define BDI_sync_congested		1
#define bdi_read_congested(bdi)		bdi_congested(*(bdi), 1 << BDI_sync_congested)

static inline int
bdi_congested(struct backing_dev_info * bdi_ptr, long bits)
{
    return 0;		//XXXX bdi_congested() always says "no"
}

//XXX queue_limits ignored
struct queue_limits {
    unsigned int			discard_granularity;
    unsigned int			discard_alignment;
    unsigned int			max_discard_sectors;
    unsigned int			max_write_zeroes_sectors;
    unsigned int			max_hw_sectors;
};

struct request_queue {
    struct list_head			queue_head;
    spinlock_t			      *	queue_lock; /* yes, a pointer (2.6.32) */
    int				      (*make_request_fn)(struct request_queue *, struct bio *);
    void			      *	queuedata;
    unsigned int			in_flight[2];
    unsigned long			queue_flags;
    struct backing_dev_info		backing_dev_info;
    struct queue_limits			limits;
    void			      (*unplug_fn)(void *);	//XXX plugging unimplemented
    struct kobject			kobj;
    unsigned int			dma_pad_mask;
    gfp_t				bounce_gfp;	/* keep zero */
//  struct mutex			sysfs_lock;
//  void			      (*request_fn_proc)(struct request_queue *);
};

#define queue_flag_clear(bit, q)	clear_bit((bit), &(q)->queue_flags)
#define queue_flag_set(bit, q)		set_bit((bit), &(q)->queue_flags)
#define queue_max_hw_sectors(q)		((q)->limits.max_hw_sectors)
#define queue_alignment_offset(a)	0
#define queue_io_min(a)			PAGE_SIZE
#define queue_io_opt(a)			PAGE_SIZE

#define queue_dma_alignment(q)		511
#define queue_logical_block_size(q)	512

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define queue_physical_block_size(a)	4096	//XXX
#endif

extern struct kobj_type blk_queue_ktype;

static inline struct request_queue *
blk_alloc_queue(gfp_t gfp)
{
    struct request_queue * q = record_alloc(q);
    kobject_init(&q->kobj, &blk_queue_ktype);
    INIT_LIST_HEAD(&q->queue_head);
    q->limits.max_hw_sectors = 4*1024*1024;
    return q;
}

struct request {
    struct request	      * next_rq;
    struct gendisk	      * rq_disk;
    struct bio		      * bio;
    uint8_t		      *	cmd;
    int				cmd_len;
    int				cmd_flags;
    int				cmd_type;
    void		      * end_io_data;
    int				errors;
    struct request_queue	*q;
    size_t			resid_len;
    int				retries;
    int				sense_len;
    int				timeout;
    void		      * special;
    char		      * sense;
};

/*** inode ***/

struct inode {
    /* initialized by init_inode() */
    int				UMC_type;	/* I_TYPE_* */
    int				UMC_fd;		/* backing usermode real fd */
    atomic_t			i_count;	/* refcount */
    umode_t			i_mode;		/* e.g. S_ISREG */
    loff_t			i_size;		/* device or file size in bytes */
    unsigned int		i_flags;	/* O_RDONLY, O_RDWR */
    struct mutex		i_mutex;

    unsigned int		i_blkbits;	/* log2(block_size) */
    struct block_device	      * i_bdev;		/* when I_TYPE_BDEV */
    dev_t			i_rdev;		/* device major/minor */

    /* unused */
//  unsigned long		i_ino;
//  unsigned int		i_nlink;
//  blkcnt_t			i_blocks;
//  void		      *	i_private;
};

#define I_TYPE_FILE			1   /* real file or real block device */
#define I_TYPE_SOCK			2   /* real socket */
#define I_TYPE_PROC			3   /* /proc thing */
#define I_TYPE_BDEV			4   /* UMC internal layered block device */

#define i_size_read(inode)		((inode)->i_size)

#define init_inode(inode, type, mode, size, oflags, fd) do { \
    record_zero(inode); \
    (inode)->UMC_type = (type); \
    (inode)->UMC_fd = (fd); \
    atomic_set(&(inode->i_count), 1); \
    (inode)->i_mode = (mode); \
    (inode)->i_size = (size); \
    (inode)->i_flags = (oflags); \
    mutex_init(&(inode)->i_mutex); \
} while (0)

static inline void
_iget(struct inode * inode)
{
    assert(inode);
    atomic_inc(&inode->i_count);
}

static inline void iput(struct inode *);    /* below */

/* unused */
struct dentry {
    struct inode	      * d_inode;
};

#define d_unhashed(dentry)		true	//XXXX

struct nameidata;

/*** file ***/

#define S_IRUGO				(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO				(S_IWUSR|S_IWGRP|S_IWOTH)

typedef struct {
    int				count;
} read_descriptor_t;

struct file_ra_state { };

struct file {
//  struct kref			kref;		//XXX
    void		      * private_data;	/* e.g. seq_file */
    struct inode	      * inode;
    fmode_t			f_openmode;
    struct address_space      * f_mapping;	/* ignored by sync_page_range */
//  struct dentry	      * f_dentry;
//  struct file_ra_state	f_ra;
};

#define file_inode(file)		((file)->inode)
#define file_accessed(filp)		DO_NOTHING()

struct file_operations {
    void	  * owner;
    int		 (* open)(struct inode *, struct file *);
    int		 (* release)(struct inode * unused, struct file *);
    long	 (* compat_ioctl)  (struct file *, unsigned int cmd, unsigned long);
    long	 (* unlocked_ioctl)(struct file *, unsigned int cmd, unsigned long);
    ssize_t	 (* write)(struct file *, char const * buf, size_t len, loff_t * ofsp);
    ssize_t	 (* read)(struct file *, void * buf, size_t len, loff_t * ofsp);
    loff_t	 (* llseek)(struct file *, loff_t, int);
};

/*** Files on disk, or real block devices ***/

static inline struct file *
filp_open_real(string_t name, int flags, umode_t mode)
{
    int fd = open(name, flags, mode);
    if (unlikely(fd < 0)) {
	return ERR_PTR(-errno);
    }

    assert((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR);

    struct stat statbuf;
    error_t const err = UMC_kernelize(fstat(fd, &statbuf));
    if (unlikely(err != E_OK)) {
	close(fd);
	return ERR_PTR(err);
    }

    /* This appears to be the way to get the size of a block device or a file */
    off_t lseek_end_ofs = lseek(fd, 0, SEEK_END); /* (go back) */ lseek(fd, 0, SEEK_SET);

    assert_imply(S_ISREG(statbuf.st_mode), statbuf.st_size == lseek_end_ofs);

#if 0	    // S_BLOCKIO_TYPE
#define S_BLOCKIO_TYPE	S_IFBLK	    /* make block devices look like block devices */
#else
#define S_BLOCKIO_TYPE	S_IFREG	    /* make block devices look like files */
#endif

    /* Hack /dev/zero to look like a big block device (or file) */
    if (S_ISCHR(statbuf.st_mode)) {
	struct stat zero_statbuf;
	int rc = stat("/dev/zero", &zero_statbuf);
	if (rc == 0 && statbuf.st_rdev == zero_statbuf.st_rdev) {
	    statbuf.st_size = 1ul << 40;
	    statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
	}
    } else if (S_ISBLK(statbuf.st_mode)) {
	statbuf.st_size = lseek_end_ofs;
	statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
    }

    sys_notice("OPEN FILE name='%s' fd=%d statbuf.st_size=%"PRIu64" lseek_end_ofs=%"PRId64"/0x%"PRIx64,
               name, fd, statbuf.st_size, lseek_end_ofs, lseek_end_ofs);

    struct file * file = record_alloc(file);
    file->inode = record_alloc(file->inode);
    init_inode(file->inode, I_TYPE_FILE, statbuf.st_mode, statbuf.st_size, flags, fd);
    return file;
}

static inline void
filp_close_real(struct file * file)
{
    assert_eq(file->inode->UMC_type, I_TYPE_FILE);
    iput(file->inode);
    record_free(file);
}

#define vfs_read(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(pread((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_write(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(pwrite((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_readv(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(preadv((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_writev(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc; \
		if ((file)->inode->UMC_type == I_TYPE_SOCK) { \
		    _rc = UMC_kernelize64(writev((file)->inode->UMC_fd, (iovec), (nvec))); \
		} else { \
		    verify_eq((file)->inode->UMC_type, I_TYPE_FILE); \
		    _rc = UMC_kernelize64(pwritev((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		    if (likely(_rc > 0)) *(seekposp) += _rc; \
		} \
		_rc; \
	    })

/* Note anachronism:  this simulates the vfs_fsync definition from LINUX_VERSION 2.6.35 */
#define vfs_fsync(file, datasync) \
	    UMC_kernelize((datasync) ? fdatasync((file)->inode->UMC_fd) \
				     : fsync((file)->inode->UMC_fd))

static inline error_t
sync_page_range(struct inode * inode, void * mapping, loff_t offset, loff_t nbytes)
{
    error_t err =  UMC_kernelize(sync_file_range(inode->UMC_fd, offset, nbytes,
	    0/* SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER) */));

    if (err == -ESPIPE) err = E_OK;	//XXX /dev/zero
    return err;
}

/*** Device ***/

struct device {
    struct kobject	        kobj;
    dev_t			devt;
    struct device	      * parent;
    struct gendisk	      * disk;
};

extern struct kobj_type device_ktype;

static inline struct device *
device_alloc(void)
{
    struct device * dev = record_alloc(dev);
    kobject_init(&dev->kobj, &device_ktype);
    return dev;
}

#define device_put(dev)			kobject_put(&dev->kobj);

#define generic_unplug_device(q)	DO_NOTHING()

struct class_device;
struct class_interface {
    int (*add)(struct class_device *cdev, struct class_interface *intf);	/* <  2.6.26 */
    void (*remove)(struct class_device *cdev, struct class_interface *intf);	/* <  2.6.26 */
    int (*add_dev)(struct device *cdev, struct class_interface *intf);		/* >= 2.6.26 */
    void (*remove_dev)(struct device *cdev, struct class_interface *intf);	/* >= 2.6.26 */
};

#define register_chrdev(major, name, fops)	(_USE(name), E_OK)
#define unregister_chrdev(major, name)		DO_NOTHING()

/*** Block Device ***/

typedef u8				blk_status_t;

#define BLK_STS_OK		0
#define BLK_STS_NOTSUPP		1
#define BLK_STS_MEDIUM		7
#define BLK_STS_RESOURCE	9
#define BLK_STS_IOERR		10

struct blk_plug_cb { void *data; };
struct blk_plug { };

#define blk_put_queue(q)		kobject_put(&(q)->kobj)
#define blk_cleanup_queue(q)		blk_put_queue(q)

#define blk_queue_max_discard_sectors(q, n) DO_NOTHING()    /* set no max */
#define blk_queue_segment_boundary(q, mask) DO_NOTHING()    /* set no rules */
#define blk_queue_stack_limits(q1, q2)	DO_NOTHING()	    /* no extra limits */
#define blk_set_stacking_limits(a)	DO_NOTHING()	    /* set no limits */
#define blk_check_plugged(a, b, c)	NULL		    /* no plug */
#define blk_finish_plug(a)		DO_NOTHING()	    /* no plug */
#define blk_start_plug(a)		DO_NOTHING()	    /* no plug */

#define blk_queue_make_request(q, fn)	((q)->make_request_fn = (fn))
#define blk_queue_max_hw_sectors(q, n)	((q)->limits.max_hw_sectors = (n))

/* Add request to queue for execution */
#define blk_execute_rq_nowait(q, disk, rq, at_head, done_fn) \
	    UMC_STUB(blk_execute_rq_nowait);	    //XXXX unused?

/* PDU allocated immediately beyond the request structure */
static inline void *
blk_mq_rq_to_pdu(struct request *rq)
{
	return rq + 1;
}

#define blk_bidi_rq(rq)                ((rq)->next_rq != NULL)

#define BDEVNAME_SIZE		32	/* Largest string for a blockdev identifier */

#define register_blkdev(major, name)		E_OK
#define unregister_blkdev(major, name)		DO_NOTHING()

#define blkdev_issue_flush(bdev, xxx)		fsync_bdev(bdev)    //XXX right?
#define blkdev_issue_discard(bdev, sector, nr_sects, gfp, flags)    (-EOPNOTSUPP)   //XXXX

#define bd_link_disk_holder(a, b)	E_OK		//XXX sysfs
#define bd_unlink_disk_holder(a, b)	DO_NOTHING()	//XXX sysfs

struct block_device {
    struct inode	  * bd_inode;
    struct block_device	  * bd_contains;
    struct gendisk	  * bd_disk;
    unsigned int	    bd_block_size;
};

#define block_size(bdev)		((bdev)->bd_block_size)
#define bdev_size(bdev)			((bdev)->bd_disk->part0.nr_sects * 512)

#define BDEV_I(inode)			({ assert_eq((inode)->UMC_type, I_TYPE_BDEV); \
					   (inode)->i_bdev; \
					})

/* Take another reference on the bdev */
static inline struct block_device *
bdgrab(struct block_device * bdev)
{
    _iget(bdev->bd_inode);
    return bdev;
}

/* Drop a reference on the bdev */
static inline void
bdput(struct block_device * bdev)
{
    assert_eq(bdev->bd_inode->UMC_type, I_TYPE_BDEV);
    iput(bdev->bd_inode);
}

/* Create a block device */
static inline struct block_device *
bdget(dev_t devt)
{
    struct block_device * bdev = record_alloc(bdev);
    struct inode * inode = record_alloc(inode);

    init_inode(inode, I_TYPE_BDEV, S_IFBLK, 0/*size*/, 0, -1);
    inode->i_bdev = bdev;
    inode->i_rdev = devt;
    inode->i_blkbits = 12;	//XXXX

    bdev->bd_inode = inode;
    bdev->bd_block_size = (1 << inode->i_blkbits);

    struct block_device * bdev_check = BDEV_I(inode);
    assert_eq(bdev_check, bdev);

//  spin_lock(&bdev_lock);
//  list_add(&bdev->bd_list, &all_bdevs);
//  spin_unlock(&bdev_lock);

    return bdev;
}

#define bdev_get_queue(bdev)		((bdev)->bd_disk->queue)
#define bdev_discard_alignment(bdev)	bdev_get_queue(bdev)->limits.discard_alignment
#define bdevname(bdev, buf) \
	    ({ snprintf((buf), BDEVNAME_SIZE, "%s", (bdev)->bd_disk->disk_name); (buf); })

#define fsync_bdev(bdev)		fsync((bdev)->bd_inode->UMC_fd)

#define set_disk_ro(disk, flag)		((disk)->part0.policy = (flag))
#define bdev_read_only(bdev)		((bdev)->bd_disk->part0.policy != 0)

struct block_device_operations {
    struct module *owner;
    int (*open) (struct block_device *, fmode_t);
    void (*release) (struct gendisk *, fmode_t);
    // int (*rw_page)(struct block_device *, sector_t, struct page *, bool);
    // int (*ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    // int (*compat_ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    // unsigned int (*check_events) (struct gendisk *disk, unsigned int clearing);
};

/*** gendisk ***/

extern struct proc_dir_entry * UMC_fuse_dev_add(const char * name, dev_t, umode_t);
extern error_t UMC_fuse_dev_remove(const char * name);

struct hd_struct {
    unsigned long			nr_sects;
    unsigned int			policy;
    unsigned int			partno;
    int32_t				in_flight[2];
    struct device		      * __dev;
};

struct gendisk {
    struct list_head			disk_list;
    struct request_queue	      * queue;
    unsigned int			major;
    int					first_minor;
    char				disk_name[32];
    void			      * private_data;
    const struct block_device_operations * fops;
    struct hd_struct			part0;
    struct block_device		      *	bdev;
};

#define disk_to_dev(disk)		((disk)->part0.__dev)
#define disk_to_bdev(disk)		((disk)->bdev)	//XXX

extern struct list_head UMC_disk_list;
extern struct spinlock UMC_disk_list_lock;

#define UMC_DEV_PREFIX	"/UMCdev/"

static inline struct block_device *
lookup_bdev(const char * path)
{
    struct block_device * bdev = NULL;
    struct gendisk * pos;
    const char *p;

    if (strncmp(path, UMC_DEV_PREFIX, sizeof(UMC_DEV_PREFIX)-1)) {
	sys_warning("Bad device name prefix: %s", path);
	return NULL;
    }

    p = path + sizeof(UMC_DEV_PREFIX) - 1;  /* skip prefix */

    spin_lock(&UMC_disk_list_lock);

    list_for_each_entry(pos, &UMC_disk_list, disk_list)
	if (!strcmp(pos->disk_name, p)) {
	    bdev = disk_to_bdev(pos);
	    assert(bdev);
	    break;
	}

    bdgrab(bdev);	/* ++refcount (under lock) */

    spin_unlock(&UMC_disk_list_lock);
    return bdev;
}

//XXX exclusivity neglected
static inline struct block_device *
open_bdev_exclusive(const char *path, fmode_t mode, void *holder)
{
    struct block_device *bdev;

    bdev = lookup_bdev(path);
    if (!bdev) {
	    sys_warning("****************** bdev %s not found", path);
	    return ERR_PTR(-ENODEV);
    }

    if ((mode & FMODE_WRITE) && bdev_read_only(bdev)) {
	    sys_warning("****************** bdev %s says it is readonly", path);
	    bdput(bdev);
	    return ERR_PTR(-EACCES);
    }

    assert_eq(bdev->bd_contains, bdev);
    assert(bdev->bd_disk);
    assert(bdev->bd_disk->fops);
    assert(bdev->bd_disk->fops->release);

    int error = bdev->bd_disk->fops->open(bdev, mode);
    if (error) {
	sys_warning("****************** bdev %s failed fops->open() %d", path, error);
	bdput(bdev);
	return ERR_PTR(error);
    }

    sys_notice("name='%s' size=%"PRIu64, bdev->bd_disk->disk_name, bdev_size(bdev));

    return bdev;
}

static inline void
close_bdev_exclusive(struct block_device *bdev, fmode_t mode)
{
    assert_eq(bdev->bd_contains, bdev);
    assert(bdev->bd_disk);
    assert(bdev->bd_disk->fops);

    sys_notice("name='%s' size=%"PRIu64, bdev->bd_disk->disk_name, bdev_size(bdev));

    if (bdev->bd_disk->fops->release)
	bdev->bd_disk->fops->release(bdev->bd_disk, mode);

    bdput(bdev);	/* --refcount */
}

/* Get a handle for a UMC internal (fake) layered block device */
static inline struct file *
filp_open_bdev(string_t name, int inflags)
{
    int flags = inflags & O_ACCMODE;
    assert(flags == O_RDONLY || flags == O_RDWR);
    fmode_t fmode = FMODE_READ | (flags == O_RDWR ? FMODE_WRITE : 0);

    struct block_device * bdev = open_bdev_exclusive(name, fmode, NULL);
    if (PTR_ERR(bdev) <= 0) {
	sys_warning("cannot open name='%s', err=%ld", name, PTR_ERR(bdev));
	return ERR_PTR(PTR_ERR(bdev));
    }

    struct file * file = record_alloc(file);
    file->inode = bdev->bd_inode;
    file->f_openmode = fmode;
    return file;
}

static inline void
filp_close_bdev(struct file * file)
{
    assert_eq(file->inode->UMC_type, I_TYPE_BDEV);
    close_bdev_exclusive(BDEV_I(file->inode), file->f_openmode);
    record_free(file);
}

static inline struct file *
filp_open(string_t name, int flags, umode_t mode)
{
    /* XXX Hack to detect internal block device names not in the real filesystem */
    if (!strncmp(name, UMC_DEV_PREFIX, sizeof(UMC_DEV_PREFIX)-1))
	/* name is intended as a UMC internal name */
	return filp_open_bdev(name, flags);
    else
	/* name is intended as a real name in the real filesystem */
	return filp_open_real(name, flags, mode);
}

static inline void
filp_close(struct file * file, void * unused)
{
    if (file->inode->UMC_type == I_TYPE_BDEV)
	filp_close_bdev(file);
    else
	filp_close_real(file);
}

static inline struct gendisk *
alloc_disk(int nminors)
{
    struct gendisk * disk = record_alloc(disk);
    assert_eq(nminors, 1);		//XXX Limitation
    disk->part0.__dev = device_alloc();
    disk->part0.__dev->disk = disk;
    return disk;
}

#define put_disk(disk)			kobject_put(&disk_to_dev(disk)->kobj)

static inline void
del_gendisk(struct gendisk * disk)
{
    UMC_fuse_dev_remove(disk->disk_name);

    spin_lock(&UMC_disk_list_lock);
    list_del(&disk->disk_list);		/* remove from UMC_disk_list */
    spin_unlock(&UMC_disk_list_lock);
    /* put_disk() occurs in a separate call */
}

static inline void
add_disk(struct gendisk * disk)
{
    dev_t devt = MKDEV(disk->major, disk->first_minor);
    struct device *dev = disk_to_dev(disk);
    dev->devt = devt;
    dev->parent = NULL;
    spin_lock(&UMC_disk_list_lock);
    list_add(&disk->disk_list, &UMC_disk_list);
    spin_unlock(&UMC_disk_list_lock);
    // register_disk(NULL, disk);
    // blk_register_queue(disk);

    umode_t mode = S_IFBLK | (disk->part0.policy ? 0440 : 0660);
    UMC_fuse_dev_add(disk->disk_name, devt, mode);
}

#define set_capacity(disk, nsectors)	((disk)->part0.nr_sects = (nsectors))
#define get_capacity(disk)		((disk)->part0.nr_sects)

#define disk_stat_read(disk, field)	0   //XXX

/* Partitions not implemented */
#define part_round_stats(cpu, part)	(_USE(cpu), _USE(part))
#define part_stat_inc(a, b, c)		DO_NOTHING()
#define part_stat_add(cpu, prt, tk, dr) DO_NOTHING(_USE(dr))
#define part_stat_read(a, b)		0
#define part_stat_lock()		E_OK
#define part_stat_unlock()		DO_NOTHING()

/*** Block I/O ***/

struct bio_vec {
	struct page     *bv_page;
	unsigned int    bv_len;
	unsigned int    bv_offset;
};

typedef void (bio_end_io_t) (struct bio *, int);

struct bio {
	/* cloned fields */
	struct block_device   * bi_bdev;
	struct bio_vec	      *	bi_io_vec;	/* the actual vec list */
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	unsigned short		bi_idx;		/* current index into bvl_vec */
	unsigned int		bi_size;	/* residual I/O count */
	sector_t		bi_sector;	/* device address in 512 byte sectors */
	unsigned long		bi_rw;		/* READ/WRITE, FUA */
	unsigned long		bi_flags;	/* status, command, etc */

	void		      (*bi_destructor)(struct bio *);	/* set by bio_clone */
	atomic_t		__bi_cnt;	/* reference count */

	bio_end_io_t	      * bi_end_io;
	struct bio	      * bi_next;	/* request queue link */
	void		      * bi_private;
	unsigned int		bi_partno;
	unsigned int		bi_max_vecs;	/* max bvl_vecs we can hold */
	int			bi_error;
};

/* bi_flags bit numbers */
#define BIO_UPTODATE			0
#define BIO_CLONED			2

#define READ				0
#define WRITE				1
#define REQ_FUA				0x100
#define REQ_COPY_USER			0x200000

#define REQ_TYPE_BLOCK_PC		0x2

#define READ_SYNC			(READ | (1 << BIO_RW_SYNCIO) | (1 << BIO_RW_UNPLUG))
#define WRITE_SYNC_PLUG			(WRITE | (1 << BIO_RW_SYNCIO))
#define WRITE_SYNC			(WRITE_SYNC_PLUG | (1 << BIO_RW_UNPLUG))

/* bi_rw flag bit numbers */
#define BIO_RW				0
#define BIO_RW_FAILFAST_DEV		1   /* 2.6.32 */
#define BIO_RW_FAILFAST_TRANSPORT	2   /* 2.6.32 */
#define BIO_RW_FAILFAST_DRIVER		3   /* 2.6.32 */
#define BIO_RW_FAILFAST			3   /* 2.6.24 */
#define BIO_RW_AHEAD			4
#define BIO_RW_BARRIER			5
#define BIO_RW_SYNCIO			6
#define BIO_RW_UNPLUG			7
#define BIO_RW_META			8
#define BIO_RW_DISCARD			9
#define BIO_RW_NOIDLE			10

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)   //XXX still in 2.6.26, not 2.6.32
#define BIO_RW_SYNC			BIO_RW_SYNCIO
#endif

#define BIO_MAX_PAGES			1024

#define bio_iovec(bio)			((bio)->bi_io_vec)
#define bio_set_dev(bio, bdev)		((bio)->bi_bdev = (bdev))
#define bio_iovec_idx(bio, idx)		(&((bio)->bi_io_vec[(idx)]))

#define op_is_write(op)			((op) & 1)
#define bio_data_dir(bio)		(op_is_write(bio_op(bio)) ? WRITE : READ)
#define bio_get_nr_vecs(bdev)		BIO_MAX_PAGES
#define bio_flagged(bio, bitno)		(((bio)->bi_flags & (1 << (bitno))) != 0)

#define bio_get(bio)			atomic_inc(&(bio)->__bi_cnt)
#define bio_endio(bio, err)		do { if ((bio)->bi_end_io) (bio)->bi_end_io((bio), (err)); } while (0)

#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);  \
	     i < (bio)->bi_vcnt;					\
	     bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

#define bio_kmalloc(gfp, maxvec)	bio_alloc((gfp), (maxvec))

static inline sector_t
blk_rq_pos(const struct request *rq)
{
    return rq->bio ? rq->bio->bi_sector : 0;
}

struct bio_set;

static inline void
bio_free(struct bio *bio, struct bio_set *bs)
{
    expect_eq(bs, NULL);
    expect_eq(atomic_read(&bio->__bi_cnt), 0);
    kfree(bio);
}

static inline void
bio_destructor(struct bio *bio)
{
    bio_free(bio, NULL);
}

static inline void
bio_put(struct bio * bio)
{
    if (!atomic_dec_and_test(&bio->__bi_cnt))
	return;

    if (bio->bi_destructor)
	bio->bi_destructor(bio);
    else
	bio_destructor(bio);
}

static inline struct bio *
bio_alloc(gfp_t gfp, unsigned int maxvec)
{
    struct bio * bio;
    bio = kzalloc(sizeof(struct bio) + maxvec * sizeof(struct bio_vec), (gfp));
    bio->bi_io_vec = (struct bio_vec *)(bio+1);
    bio->bi_max_vecs = maxvec;
    bio->bi_destructor = bio_destructor;
    bio->bi_flags |= 1<<BIO_UPTODATE;
    atomic_set(&bio->__bi_cnt, 1);
    return bio;
}

static inline struct bio *
bio_clone(struct bio * bio, gfp_t gfp)
{
    struct bio * new_bio = bio_kmalloc(gfp, bio->bi_max_vecs);
    new_bio->bi_bdev	= bio->bi_bdev;
    new_bio->bi_vcnt	= bio->bi_vcnt;
    new_bio->bi_idx	= bio->bi_idx;
    new_bio->bi_size	= bio->bi_size;
    new_bio->bi_sector	= bio->bi_sector;
    new_bio->bi_rw	= bio->bi_rw;
    new_bio->bi_flags	= bio->bi_flags;

    memcpy(new_bio->bi_io_vec, bio->bi_io_vec, new_bio->bi_vcnt * sizeof(*new_bio->bi_io_vec));

    new_bio->bi_destructor = bio_destructor;
    atomic_set(&new_bio->__bi_cnt, 1);
    new_bio->bi_flags |= 1<<BIO_CLONED;

    return new_bio;
}

static inline void
__bio_add_page(struct bio *bio, struct page *page, unsigned int len, unsigned int off)
{
	struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

	WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
	assert(bio->bi_vcnt < bio->bi_max_vecs);

	bv->bv_page = page;
	bv->bv_offset = off;
	bv->bv_len = len;

	bio->bi_size += len;
	bio->bi_vcnt++;
}

/* Append a page (or part of a page) to the data area for the bio */
static inline int
bio_add_page(struct bio * bio, struct page * page, unsigned int len, unsigned int off)
{
    if (bio->bi_vcnt >= bio->bi_max_vecs)
	return 0;
    __bio_add_page(bio, page, len, off);
    return len;
}

#define bio_add_pc_page(q, bio, page, bytes, ofs) \
					bio_add_page((bio), (page), (bytes), (ofs))

static inline int
submit_bio(int rw, struct bio * bio)
{
    bio->bi_rw |= rw;
    return bio->bi_bdev->bd_disk->queue->make_request_fn(bio->bi_bdev->bd_disk->queue, bio);
}

static inline int
_submit_bio(struct bio * bio)
{
    return bio->bi_bdev->bd_disk->queue->make_request_fn(bio->bi_bdev->bd_disk->queue, bio);
}

#define generic_make_request(bio)	_submit_bio(bio)

struct bio_set				{ };	    /* bio_set not implemented */
#define BIO_POOL_SIZE			IGNORED	    /* bio_set */

#define bioset_integrity_create(bioset, x) (-ENOTSUP)

static inline struct bio_set *
bioset_create(unsigned int pool_size, unsigned int front_pad)
{
    return (struct bio_set *)(-1);  /* XXXX non-NULL fakes success, will be otherwise ignored */
}

static inline void
bioset_free(struct bio_set * bs)
{
    DO_NOTHING();
}

static inline struct bio *
bio_alloc_bioset(gfp_t gfp, unsigned int n, struct bio_set * bs_ignored)
{
    return bio_alloc(gfp, n);
}

/*** Sockets ***/

struct socket;
struct sock;
enum sock_type;
struct poll_table_struct { };
struct ts_config;
struct ts_state;
#include <net/checksum.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/in6.h>
/* do not #include <linux/socket.h> */

struct sk_prot {
    void		  (*disconnect)(struct sock *, int);
};

struct sock {
    int			    fd;			    /* same as inode->UMC_fd (backing fd) */
    uint16_t		    sk_sport;
    uint16_t		    sk_dport;

    long		    sk_rcvtimeo;
    long		    UMC_rcvtimeo;	    /* last timeout set in real socket */
    long		    sk_sndtimeo;	    //XXX
    int			    sk_rcvbuf;		    //XXX
    int			    sk_sndbuf;		    //XXX

    struct socket	  * sk_socket;		    /* unimplemented */
    __u32		    sk_priority;	    /* unimplemented */
    int			    sk_wmem_queued;	    /* unimplemented */
    gfp_t		    sk_allocation;	    /* unimplemented */
    unsigned char	    sk_reuse:4;		    /* unimplemented */
    unsigned char	    sk_userlocks:4;	    /* unimplemented */

    int			    sk_state;		    /* e.g. TCP_ESTABLISHED */
    rwlock_t		    sk_callback_lock;	    /* protect changes to callbacks */	//XXXXX
    void		  * sk_user_data;
    void		  (*sk_data_ready)(struct sock *, int); /* protocol callbacks */
    void		  (*sk_write_space)(struct sock *);
    void		  (*sk_state_change)(struct sock *);
    struct sk_prot	  * sk_prot;
    struct sk_prot	    sk_prot_s;

    /* TCP */
    u32			    copied_seq;		    /* unimplemented */
    u32			    rcv_nxt;		    /* unimplemented */
    u32			    snd_una;		    /* unimplemented */
    u32			    write_seq;		    /* unimplemented */

    bool		    is_listener;

    /* Netlink */
    struct sock		  * sk;		/* self-pointer hack */
    struct netlink_callback *cb;
    struct mutex	  * cb_mutex;
    struct mutex	    cb_def_mutex;
    void		    (*netlink_rcv)(struct sk_buff *skb);

    sys_event_task_t	    wr_poll_event_task;	/* thread of event thread for this fd */
    sys_poll_entry_t	    wr_poll_entry;	/* unique poll descriptor for this fd */
    sys_event_task_t	    rd_poll_event_task;
    sys_poll_entry_t	    rd_poll_entry;
    struct _irqthread     * rd_poll_event_thread;

    uint16_t sk_family;
    union {
	struct {
	    struct in_addr saddr;
	    struct in_addr daddr;
	} inet_sk;
	struct {
	    struct in6_addr saddr;
	    struct in6_addr daddr;
	} inet6_sk;
    };
};

#define netlink_sock			sock
#define	tcp_sock			sock

#define nlk_sk(sk)			(sk)

#define TCP_ESTABLISHED			1

static inline struct tcp_sock *
tcp_sk(struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

#define inet_sk(sk)			(&(sk)->inet_sk)
#define inet6_sk(sk)			(&(sk)->inet6_sk)

#define IPV6_ADDR_LINKLOCAL		0x0020U
#define IPV6_ADDR_UNICAST		0x0001U
#define ipv6_addr_type(x)		IPV6_ADDR_UNICAST   //XXX LINKLOCAL

#define ipv6_addr_equal(x, y)		(!memcmp((x), (y), sizeof(struct in6_addr)))

#define NIP6(addr)			(addr).s6_addr16[0], \
					(addr).s6_addr16[1], \
					(addr).s6_addr16[2], \
					(addr).s6_addr16[3], \
					(addr).s6_addr16[4], \
					(addr).s6_addr16[5], \
					(addr).s6_addr16[6], \
					(addr).s6_addr16[7]

struct socket_ops {
    ssize_t (*sendpage)  (struct socket *, struct page *, int, size_t, int);
    int     (*setsockopt)(struct socket *, int, int, void *, socklen_t);
    int     (*getname)   (struct socket *, struct sockaddr *, socklen_t *addr_len, int peer);
    int     (*bind)	 (struct socket *, struct sockaddr *, socklen_t addr_len);
    int     (*connect)   (struct socket *, struct sockaddr *, socklen_t addr_len, int flags);
    int     (*listen)    (struct socket *, int len);
    int     (*accept)    (struct socket *, struct socket *, int flags, bool kern);
    int     (*shutdown)  (struct socket *, int);
    void    (*discon)	 (struct socket *);
};

#define RCV_SHUTDOWN			1
#define SEND_SHUTDOWN			2

typedef enum { SS_unused } socket_state;

struct socket {
    struct inode	    vfs_inode;
    socket_state	    state;
    unsigned long	    flags;
    bool		    nonblocking;	/* NONBLOCK setting */
    struct file		  * file;
    struct sock		  * sk;			/* points at embedded sk_s */
    struct socket_ops     * ops;		/* points at embedded ops_s */
    struct sock		    sk_s;
    struct socket_ops	    ops_s;
};

#define SOCKET_I(inode)			({ assert_eq((inode)->UMC_type, I_TYPE_SOCK); \
					   container_of((inode), struct socket, vfs_inode); \
					})

#define sock_of_sk(sk)			container_of((sk), struct socket, sk_s)

#define ip_compute_csum(data, len)	0	//XXXX

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_NOSPACE		2

#define kernel_accept(sock, newsock, flags)	    UMC_sock_accept((sock), (newsock), (flags))
#define kernel_sock_shutdown(sock, k_how)	    UMC_sock_shutdown((sock), (k_how))
#define kernel_setsockopt(sock, level, optname, optval, optlen) \
	    UMC_setsockopt(sock, level, optname, optval, optlen)

/* The sock->ops point to these shim functions */
extern ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
				size_t size, int flags);
extern error_t UMC_setsockopt(struct socket * sock, int level, int optname,
				void *optval, socklen_t optlen);
extern error_t UMC_sock_connect(struct socket * sock, struct sockaddr * addr,
				socklen_t addrlen, int flags);
extern error_t UMC_sock_bind(struct socket * sock, struct sockaddr *addr, socklen_t addrlen);
extern error_t UMC_sock_listen(struct socket * sock, int backlog);
extern error_t UMC_sock_accept(struct socket * sock, struct socket ** newsock, int flags);
extern error_t UMC_sock_shutdown(struct socket * sock, int k_how);
extern void UMC_sock_discon(struct sock * sk, int XXX);
extern error_t UMC_sock_getname(struct socket * sock, struct sockaddr * addr,
				socklen_t * addrlen, int peer);

/* These are the original targets of the sk callbacks before the app intercepts them */
extern void UMC_sock_cb_read(struct sock *, int obsolete);
extern void UMC_sock_cb_write(struct sock *);
extern void UMC_sock_cb_state(struct sock *);

extern void UMC_sock_recv_event(void * env, uintptr_t events, error_t err);
extern void UMC_sock_xmit_event(void * env, uintptr_t events, error_t err);

struct msghdr;
extern ssize_t kernel_sendmsg(struct socket * sock, struct msghdr * msg,
				struct kvec * vec, int nvec, size_t nbytes);

#define sock_recvmsg(sock, msg, nb, f) \
	    UMC_sock_recvmsg((sock), (msg), (nb), (f), FL_STR)
extern error_t UMC_sock_recvmsg(struct socket * sock, struct msghdr * msg,
		size_t nbytes, int flags, sstring_t caller_id);

#define kernel_recvmsg(sock, msg, vec, nsg, nb, f) \
	    UMC_kernel_recvmsg((sock), (msg), (vec), (nsg), (nb), (f), FL_STR)
extern error_t UMC_kernel_recvmsg(struct socket * sock, struct msghdr * msg,
			struct kvec * kvec, int num_sg, size_t nbytes,
			int flags, sstring_t caller_id);

/* Initialize a socket structure around an open socket fd */
static inline void
UMC_sock_init(struct socket * sock, struct file * file)
{
    int fd = file->inode->UMC_fd;

    /* Set pointers to internal embedded structures */
    sock->ops = &sock->ops_s;
    sock->sk = &sock->sk_s;
    sock->sk->sk_prot = &sock->sk->sk_prot_s;

    sock->sk->fd = fd;
    sock->file = file;
    sock->flags = 0;

    /* Socket operations callable by application */
    struct socket_ops * wops = (struct socket_ops *)sock->ops;
    wops->bind = UMC_sock_bind;
    wops->connect = UMC_sock_connect;
    wops->getname = UMC_sock_getname;
    wops->listen = UMC_sock_listen;
    wops->shutdown = UMC_sock_shutdown;
    wops->setsockopt = UMC_setsockopt;
    wops->sendpage = sock_no_sendpage;
    sock->sk->sk_prot->disconnect = UMC_sock_discon;

    /* State change callbacks to the application, delivered by event_task */
    sock->sk->sk_state_change = UMC_sock_cb_state;
    sock->sk->sk_data_ready = UMC_sock_cb_read;
    sock->sk->sk_write_space = UMC_sock_cb_write;

    rwlock_init(&sock->sk->sk_callback_lock);
}

extern int UMC_socketpair(int domain, int type, int protocol, int sv[2]);
extern void UMC_sock_filladdrs(struct socket * sock);

//XXX TUNE how sockets relate to event threads
/* For now using one "softirq" thread for transmit-ready notifications shared by
 * ALL sockets, and one softirq thread for receive processing for EACH socket.
 */
static inline void
UMC_sock_poll_start(struct socket * sock, void (*recv)(struct sock *, int),
					  void (*xmit)(struct sock *),
					  void (*state)(struct sock *),
					  sstring_t recv_thread_name)
{
    sock->sk->sk_data_ready = recv ?: UMC_sock_cb_read;
    sock->sk->sk_write_space = xmit ?: UMC_sock_cb_write;
    sock->sk->sk_state_change = state ?: UMC_sock_cb_state;
    if (xmit) {
	sock->sk->wr_poll_event_task = UMC_irqthread->event_task;
	sock->sk->wr_poll_entry = sys_poll_enable(sock->sk->wr_poll_event_task,
					  UMC_sock_xmit_event, sock, sock->sk->fd,
					  SYS_SOCKET_XMIT_ET, "socket_xmit_poll_entry");
    }
    if (recv || state) {
	sock->sk->rd_poll_event_thread = irqthread_run("%s", recv_thread_name);
	sock->sk->rd_poll_event_task = sock->sk->rd_poll_event_thread->event_task;
	sock->sk->rd_poll_entry = sys_poll_enable(sock->sk->rd_poll_event_task,
					  UMC_sock_recv_event, sock, sock->sk->fd,
					  SYS_SOCKET_RECV_ET, "socket_recv_poll_entry");
    }
}

/* Wrap a backing real usermode SOCKET fd inside a simulated kernel struct file * */
//XXX Support for fget/fput presently limited to sockets, one reference only
static inline struct file *
_fget(unsigned int fd)
{
    struct file * file = record_alloc(file);
    struct socket * sock = record_alloc(sock);
    file->inode = &sock->vfs_inode;
    init_inode(file->inode, I_TYPE_SOCK, 0, 0, 0, fd);
    UMC_sock_init(SOCKET_I(file->inode), file);
    return file;
}

/* This is used by SCST to grab an fd already opened by the usermode daemon */
static inline struct file *
fget(unsigned int real_fd)
{
    int fd = dup(real_fd);
    if (fd < 0) {
	sys_warning("fget could not dup() incoming fd=%d err=%d", real_fd, errno);
	return NULL;
    }
    struct file * file = _fget(fd);	/* caller still owns the original fd */
    struct socket * sock = SOCKET_I(file->inode);
    char thread_name[32];
    UMC_sock_filladdrs(sock);
    sock->sk->sk_state = TCP_ESTABLISHED;
    snprintf(thread_name, sizeof(thread_name), "%d.%d.%d.%d",
						NIPQUAD(inet_sk(sock->sk)->daddr));
    /* use whatever callbacks are already in the sk */
    UMC_sock_poll_start(sock, sock->sk->sk_data_ready, sock->sk->sk_write_space,
						sock->sk->sk_state_change, thread_name);
    return file;
}

extern int UMC_socket(int domain, int type, int protocol);

/* Does not enable poll events or start a receive handler thread for the socket */
static inline int
sock_create_kern(int family, int type, int protocol, struct socket **newsock)
{
    int fd = UMC_socket(family, type, protocol);
    if (unlikely(fd < 0)) {
	*newsock = NULL;
	return fd;	/* -errno */
    }

    struct file * file = _fget(fd);
    if (!file) {
	close(fd);
	*newsock = NULL;
	return -ENOMEM;
    }

    *newsock = SOCKET_I(file->inode);

    if(type & SOCK_NONBLOCK)
	(*newsock)->nonblocking = true;

    return E_OK;
}

struct fput_finish_work {
    struct _irqthread		  * irqthread;
    struct work_struct		    work;
};

static inline void
_fput_finish_work_fn(struct _irqthread * irqthread)
{
    irqthread_stop(irqthread);
    irqthread_destroy(irqthread);
}

static inline void
fput_finish_work_fn(struct work_struct * work)
{
    struct fput_finish_work * ffw;
    ffw = container_of(work, struct fput_finish_work, work);
    _fput_finish_work_fn(ffw->irqthread);
    record_free(ffw);
}

static inline void
fput(struct file * sockfile)
{
    assert_eq(sockfile->inode->UMC_type, I_TYPE_SOCK);
    struct sock * sk = SOCKET_I(sockfile->inode)->sk;

    if (sk->wr_poll_event_task)
	sys_poll_disable(sk->wr_poll_event_task, sk->wr_poll_entry);

    if (sk->rd_poll_event_task) {
	sys_poll_disable(sk->rd_poll_event_task, sk->rd_poll_entry);

	if (sys_thread_current() != sk->rd_poll_event_thread->SYS)
	    _fput_finish_work_fn(sk->rd_poll_event_thread);
	else {
	    /* irqthread can't shut itself down; use a helper */
	    struct fput_finish_work * ffw = record_alloc(ffw);
	    INIT_WORK(&ffw->work, fput_finish_work_fn);
	    ffw->irqthread = sk->rd_poll_event_thread;
	    schedule_work(&ffw->work);
	}
    }

    iput(sockfile->inode);
    record_free(sockfile);
}

#define sock_release(sock)		fput((sock)->file)

/*** seq ops for /proc and /sys ***/

struct proc_inode {
    struct kobject * kobj;		/* 2.6.26 */	//XXXXX
    struct proc_dir_entry * pde;	/* 2.6.24 */
    struct inode			vfs_inode;
};

#define PROC_I(inode)			({ assert_eq((inode)->UMC_type, I_TYPE_PROC); \
					   container_of(inode, struct proc_inode, vfs_inode); \
					})

#define PDE(inode)			(PROC_I(inode)->pde)

/* PROCFS */

#define seq_lseek			NULL	/* unused */

struct seq_file {
    struct seq_operations const   * op;		/* start, show, next, stop */
    union {
	void			  * private;	/* 2.6.24 */
	void			  * priv;	/* 2.6.26 */
    };
    string_t			    reply;	/* accumulates seq_printfs */
};

struct seq_operations {
    void		      * (*start)(struct seq_file *, loff_t * pos);
    void		      * (*next)(struct seq_file *, void *, loff_t * pos);
    void			(*stop)(struct seq_file *, void *);
    int				(*show)(struct seq_file *, void *);
};

/* Format into a string and append to seq->reply */
#define seq_printf(seq, fmtargs...) \
    ((seq)->reply = string_concat_free((seq)->reply, sys_sprintf(""fmtargs)))

static inline error_t
seq_putc(struct seq_file * seq, char c)
{
    seq_printf(seq, "%c", c);
    return E_OK;
}

static inline error_t
seq_puts(struct seq_file * seq, string_t s)
{
    seq_printf(seq, "%s", s);
    return E_OK;
}

static inline error_t
seq_open(struct file * file, struct seq_operations const * ops)
{
    struct seq_file * seq = record_alloc(seq);
    assert_eq(file->private_data, NULL);
    file->private_data = seq;
    seq->op = ops;
    return E_OK;
}

static inline error_t
seq_release(struct inode * unused, struct file * file)
{
    struct seq_file * seq_file = file->private_data;
    file->private_data = NULL;
    record_free(seq_file);
    return E_OK;
}

static inline error_t
single_open(struct file * file, int (*show)(struct seq_file *, void *), void * data)
{
    struct seq_operations *op = record_alloc(op);
    op->show = show;
    error_t err = seq_open(file, op);
    if (err == E_OK) {
	((struct seq_file *)file->private_data)->private = data;
    }
    return err;
}

static inline error_t
single_release(struct inode * inode, struct file * file)
{
    const struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
    int rc = seq_release(inode, file);
    record_free(op);
    return rc;
}

static inline struct list_head *
seq_list_start(struct list_head *head, loff_t pos)
{
    struct list_head *lh;
    list_for_each(lh, head) {
	if (pos-- == 0) {
	    return lh;
	}
    }
    return NULL;	/* not found */
}

static inline struct list_head *
seq_list_next(void *v, struct list_head *head, loff_t *ppos)
{
    struct list_head *lh;
    lh = ((struct list_head *)v)->next;
    ++*ppos;
    return lh == head ? NULL : lh;
}

/* Use the seq_ops to format and return some state */
static inline void
seq_fmt(struct seq_file * seq)
{
    if (!seq->op->show) return;

    if (!seq->op->start) {
	seq->op->show(seq, NULL);    //XXX Right?
	return;
    }

    loff_t pos = 0;
    void * list_item;

    list_item = seq->op->start(seq, &pos);

    while (list_item) {
	error_t rc = seq->op->show(seq, list_item);
	assert_eq(rc, E_OK);
	list_item = seq->op->next(seq, list_item, &pos);
    }

    seq->op->stop(seq, list_item);
}

static inline ssize_t
seq_read(struct file * file, void * buf, size_t size, loff_t * lofsp)
{
    struct seq_file * seq = file->private_data;
    assert_ge(*lofsp, 0);

    seq_fmt(seq);   /* generate printable representation */

    size_t reply_size = seq->reply ? strlen(seq->reply) : 0;

    if (*(size_t *)lofsp >= reply_size) {
	reply_size = 0;
    } else {
	reply_size -= *lofsp;
    }

    if (reply_size > size) reply_size = size;

    if (reply_size) {
	memcpy(buf, seq->reply + *lofsp, reply_size);
	*lofsp += reply_size;
    }

    if (seq->reply) vfree(seq->reply);

    return (ssize_t)reply_size;
}

/* /proc and/or /sys simulated by mapping our proc_dir_entry tree to the FUSE filesystem API */

/* Internal representation of (simulated) /proc tree */
struct proc_dir_entry {
    struct proc_dir_entry	      * parent;	    /* root's parent is NULL */
    struct proc_dir_entry	      * sibling;    /* null terminated list */
    struct proc_dir_entry	      * child;	    /* first child (if nonempty DIR) */
    struct module		      * owner;	    /* still in 2.6.24 */
    const struct file_operations      *	proc_fops;
    void			      * data;
    size_t				size;
    umode_t				mode;
    dev_t				devt;
    time_t				atime;
    time_t				mtime;
    u8					namelen;
    char				name[1];    /* space for '\0' */
};

/* Application calls here to create/update PDE tree -- a NULL parent refers to the root node */
extern struct proc_dir_entry * pde_create(char const *, umode_t, struct proc_dir_entry *,
						const struct file_operations *, void *);

extern error_t pde_remove(char const * name, struct proc_dir_entry * parent);

extern struct proc_dir_entry * UMC_fuse_module_mkdir(char * modname);
extern error_t UMC_fuse_module_rmdir(char * modname);

#define proc_create_data(name, mode, parent, fops, data) \
	    pde_create((name), (mode), (parent), (fops), (data))

#define proc_create(name, mode, parent, fops) \
		proc_create_data((name), (mode), (parent), (fops), NULL)

#define create_proc_entry(name, mode, parent) \
		proc_create_data((name), (mode), (parent), NULL, NULL)

#define proc_mkdir(name, parent)	    \
		proc_create_data((name), PROC_DIR_UMODE, (parent), NULL, NULL)

#define PROC_ROOT_UMODE			(S_IFDIR | 0555)
#define PROC_DIR_UMODE			(S_IFDIR | 0555)
#define PROC_FILE_UMODE_R		(S_IFREG | 0444)
#define PROC_FILE_UMODE_RW		(S_IFREG | 0664)

#define remove_proc_entry(name, parent) pde_remove(name, (parent))

/* These are for accessing "module_param_named" variables */
//XXX You can write them, but unless someone then notices the changed value, nothing happens

extern struct proc_dir_entry * UMC_module_param_create(char const *, void *, size_t,
						umode_t, struct module *);

extern error_t UMC_module_param_remove(char const * name, struct module *);

/* Each instance in the source of module_param_named() here defines two functions to add and
 * remove a reference to the named variable in the PDE tree.  The functions are called from
 * the application compatibility init and exit functions.
 */
#define module_param_named(procname, varname, vartype, modeperms) \
 extern void CONCAT(UMC_param_create_, procname)(void); \
	void CONCAT(UMC_param_create_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    UMC_module_param_create(#procname, &varname, sizeof(varname), \
				    (modeperms), THIS_MODULE); \
	} \
 \
 extern void CONCAT(UMC_param_remove_, procname)(void); \
	void CONCAT(UMC_param_remove_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    UMC_module_param_remove(#procname, THIS_MODULE); \
	}

#define module_param(var, type, mode)	module_param_named(var, var, type, (mode))

/* Start/control the FUSE thread */
extern error_t UMC_fuse_start(const char * mountpoint);
extern error_t UMC_fuse_stop(void);
extern error_t UMC_fuse_exit(void);

/*** iput ***/

static inline void
iput(struct inode * inode)
{
    assert(inode);
    if (!atomic_dec_and_test(&inode->i_count))
	return;

    mutex_destroy(&inode->i_mutex);

    switch (inode->UMC_type) {
    case I_TYPE_FILE:
	sys_notice("CLOSE real file/bdev fd=%d", inode->UMC_fd);
	expect_ne(inode->UMC_fd, -1);
	close(inode->UMC_fd);
	record_free(inode);
	break;
    case I_TYPE_SOCK:
	sys_notice("CLOSE socket fd=%d", inode->UMC_fd);
	expect_ne(inode->UMC_fd, -1);
	close(inode->UMC_fd);
	record_free(SOCKET_I(inode));   /* inode embedded */
	break;
#if 0	/* Shouldn't come through here with curent logic in fuse.c */
    case I_TYPE_PROC:
	expect_eq(inode->UMC_fd, -1);
	record_free(PROC_I(inode));	/* inode embedded */
	break;
#endif
    case I_TYPE_BDEV:
	expect_eq(inode->UMC_fd, -1);
	record_free(BDEV_I(inode));
	record_free(inode);
	break;
    default:
	sys_warning("Bad I_TYPE 0x%x", inode->UMC_type);
    }
}

/*** Scatter/gather ***/

/* page_link may contain pointer to a chained struct scatterlist */
struct scatterlist {
    unsigned long   page_link;
    uint32_t	    offset;
    uint32_t	    length;
};

#define _SG_CHAIN			0x1UL
#define _SG_LAST			0x2UL
#define _SG_PTR_FLAGS			(_SG_CHAIN | _SG_LAST)

#define sg_is_chain(sg)			(((sg)->page_link & _SG_CHAIN) != 0)
#define sg_is_last(sg)			(((sg)->page_link & _SG_LAST) != 0)
#define sg_mark_end(sg)	\
	    ((sg)->page_link = ((sg)->page_link | _SG_LAST) & ~_SG_CHAIN)

#define sg_chain_ptr(sg)		((struct scatterlist *)((sg)->page_link & ~_SG_PTR_FLAGS))
#define sg_page(sg)			((struct page *)       ((sg)->page_link & ~_SG_PTR_FLAGS))
#define sg_assign_page(sg, page) \
	    ((sg)->page_link = ((uintptr_t)(page) | ((sg)->page_link & _SG_PTR_FLAGS)))

#define sg_copy_to_buffer(sgl, sg_count, buf, buflen)	UMC_STUB(sg_copy_to_buffer)
#define sg_copy_from_buffer(sgl, sg_count, buf, buflen)	UMC_STUB(sg_copy_from_buffer)

struct page;

static inline void
sg_set_page(struct scatterlist *sg, struct page *page, unsigned int len, unsigned int offset)
{
    sg_assign_page(sg, page);
    sg->offset = offset;
    sg->length = len;
}

#define sg_set_buf(sg, addr, length)	sg_set_page((sg), virt_to_page(addr), \
						    (length), virt_to_page_ofs(addr))

#define sg_virt(sg)			(page_address(sg_page(sg)) + (sg)->offset)

#define sg_init_table(sg, nents)	(memset((sg), 0, sizeof(*(sg)) * (nents)), \
					 sg_mark_end(&(sg)[(nents)-1]))

#define sg_init_one(sg, addr, length)	do { sg_init_table((sg), 1); \
					     sg_set_buf((sg), (addr), (length)); } while (0)

#define for_each_sg(sglist, sg, nr, i)  for ((i) = 0, (sg) = (sglist); (i) < (nr); (i)++, (sg)++)

struct sg_table {
    struct scatterlist	  * sgl;
    unsigned int	    orig_nents;
    unsigned int	    nents;
};

static inline int
sg_alloc_table(struct sg_table *table, unsigned int nents, gfp_t gfp)
{
    struct scatterlist *sg;
    unsigned int max_ents = PAGE_SIZE/sizeof(struct scatterlist);

    record_zero(table);

    if (nents == 0)
	return -EINVAL;
    if (WARN_ON_ONCE(nents > max_ents))
	return -EINVAL;

    sg = kzalloc(nents * sizeof(struct scatterlist), gfp);
    if (unlikely(!sg)) {
	return -ENOMEM;
    }

    sg_mark_end(&sg[nents - 1]);

    table->nents = table->orig_nents = nents;
    table->sgl = sg;

    return E_OK;
}

static inline int
sg_free_table(struct sg_table *table)
{
    kfree(table->sgl);
    table->sgl = NULL;
    return E_OK;
}

/********** Misc **********/

/*** Sleepable rw_semaphore ***/

struct rw_semaphore {
    rwlock_t				rwlock;
    wait_queue_head_t			waitq;
};

#define RW_SEM_UNLOCKED(rwname)		{ .rwlock = RW_LOCK_UNLOCKED(rwname), \
					  .waitq =  WAIT_QUEUE_HEAD_INIT(rwname) }

#define DECLARE_RWSEM(rw_sem)		struct rw_semaphore rw_sem = RW_SEM_UNLOCKED(rw_sem)

#define down_read_trylock(rw_sem)	read_lock_try(&(rw_sem)->rwlock)
#define down_write_trylock(rw_sem)	write_lock_try(&(rw_sem)->rwlock)

#define down_read(rw_sem)		wait_event((rw_sem)->waitq, down_read_trylock(rw_sem))
#define down_write(rw_sem)		wait_event((rw_sem)->waitq, down_write_trylock(rw_sem))

#define up_read(rw_sem)			({  read_unlock(&(rw_sem)->rwlock); wake_up_one(&(rw_sem)->waitq); })
#define up_write(rw_sem)		({ write_unlock(&(rw_sem)->rwlock); wake_up_all(&(rw_sem)->waitq); })

#define MAX_SCHEDULE_TIMEOUT		JIFFY_MAX

/*** Unaligned access ***/

#define _LINUX_UNALIGNED_ACCESS_OK_H	    /* avoid access_ok.h */
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

/*** Netlink (implemented as UDP/IPv4) ***/

extern void genl_rcv(struct sk_buff *skb);

#include <linux/netlink.h>

#define UMC_NETLINK_PORT 1234u	/* UDP port for simulated netlink */

extern error_t UMC_netlink_xmit(struct sock *sk, struct sk_buff *skb, u32 pid, u32 group, int nonblock);

#define netlink_unicast(sk, skb, pid, nonblock) \
    UMC_netlink_xmit((sk), (skb), (pid), 0, (nonblock))

#define netlink_broadcast(sk, skb, pid, group, flags) \
    UMC_netlink_xmit((sk), (skb), (pid), (group), 0)

#define read_pnet(pnet)			    (&init_net)
#define write_pnet(pnet, x)		    DO_NOTHING()
#define nl_dump_check_consistent(cb, nlh)   DO_NOTHING()
#define netlink_set_err(ssk, portid, group, code)   0	    //XXX
#define netlink_has_listeners(sk, group)	    true    //XXX

struct netlink_ext_ack
{
    const struct nlattr *bad_attr;
};

typedef struct { }			possible_net_t;

struct net {
    struct sock			      * genl_sock;
};

extern struct net init_net;

#define GENL_HDRLEN			NLMSG_ALIGN(sizeof(struct genlmsghdr))
#define GENL_NAMSIZ			16
#define GENL_ADMIN_PERM			0x01
#define SLAB_PANIC			0x00040000UL
struct genl_family;
#include <net/genetlink.h>

/*** Hashing and Crypto ***/

#if 0	    //XXX crc32c
#include <linux/crc32c.h>		// lib/libcrc32c.c
#else
extern uint32_t crc32c_uniq;		//XXXX hack makes these unique -- not good for matching
#define crc32c(x, y, z)			(++crc32c_uniq)	//XXXX
#endif

/* XXXX crypto_hash calls not yet translated to usermode */
struct hash_desc {
    struct crypto_hash		  * tfm;
    uint32_t			    flags;
};

struct shash_desc {
    void			  * tfm;
};

struct ahash_request { };

#define ahash_request_set_callback(a, b, c, d)		UMC_STUB(ahash_request_set_callback)
#define ahash_request_set_crypt(a, b, c, d)		UMC_STUB(ahash_request_set_crypt)
#define ahash_request_set_tfm(a, b)			UMC_STUB(ahash_request_set_tfm)

#define CRYPTO_ALG_ASYNC				0x00000080
#define CRYPTO_MAX_ALG_NAME				128
#define CRYPTO_MINALIGN					8
#define CRYPTO_MINALIGN_ATTR	__attribute__ ((__aligned__(CRYPTO_MINALIGN)))

#define crypto_has_alg(name_str, x, flag)		false
#define crypto_alloc_hash(type_str, x, alg)		NULL		//XXXX
#define crypto_hash_init(hash)				E_OK		//XXXX
#define crypto_hash_update(hash, sg, nbytes)		E_OK		//XXXX
#define crypto_hash_final(hash, id)			E_OK		//XXXX
#define crypto_free_hash(tfm)				DO_NOTHING()	//XXXX

#define crypto_ahash_digestsize(h)			UMC_STUB(crypto_ahash_digestsize)
#define crypto_ahash_final(h)				UMC_STUB(crypto_ahash_final)
#define crypto_ahash_init(h)				UMC_STUB(crypto_ahash_init)
#define crypto_ahash_reqsize(h)				UMC_STUB(crypto_ahash_reqsize)
#define crypto_ahash_reqtfm(h)				UMC_STUB(crypto_ahash_reqtfm)
#define crypto_ahash_update(h)				UMC_STUB(crypto_ahash_update)
#define crypto_alloc_ahash(a, b, c)			NULL		//XXXX
#define crypto_alloc_shash(a, b, c)			NULL		//XXXX
#define crypto_free_ahash(h)				UMC_STUB(crypto_free_ahash)
#define crypto_free_shash(h)				UMC_STUB(crypto_free_shash)
#define crypto_shash_descsize(h)			UMC_STUB(crypto_shash_descsize)

/* There are here mainly to keep them compiling */
#include <linux/idr.h>
#include <linux/rbtree.h>
#include <linux/ioctl.h>
#include <linux/swab.h>

void __exit idr_exit_cache(void);

//#undef pr_fmt	//XXX

////////////////////////////////////////////////////////////////////////////////
////// Stub out some definitions unused in usermode builds		  //////
////////////////////////////////////////////////////////////////////////////////

typedef void dlm_lockspace_t;
struct dlm_lksb { };

#define dlm_new_lockspace(name, namelen, lockspace, flags, lvblen) \
					UMC_STUB(dlm_new_lockspace, 0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
enum {
    DLM_LSFL_NEWEXCL = 0
};
#endif

typedef void (*ib_comp_handler)(void *cq, void *cq_context);

struct ib_device { };
struct ib_event;

static inline struct ib_cq *
ib_create_cq(struct ib_device *device, ib_comp_handler comp_handler,
	    void (*event_handler)(struct ib_event *, void *), void *cq_context,
	    unsigned int cqe, int comp_vector)
{
    return NULL;    //XXX ib_create_cq
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define ib_alloc_pd(device, flags)	NULL	//XXX
#else
#define ib_alloc_pd(device)		NULL	//XXX
#endif

struct ib_cq_init_attr;

#define PF_NOFREEZE			IGNORED
#define DEFAULT_SEEKS			IGNORED

struct mm_struct { void * mmap_sem; };
typedef void * mm_segment_t;
enum km_type { FROB };
struct vm_area_struct;

struct shrinker {
    void * count_objects;
    void * scan_objects;
    int seeks;
    int (*shrink)(int, gfp_t);
};
struct shrink_control { int nr_to_scan; };
#define register_shrinker(shrinker)	DO_NOTHING( _USE(shrinker) )
#define unregister_shrinker(shrinker)	DO_NOTHING()

#define get_io_context(gfp, x)		NULL
#define put_io_context(c)		DO_NOTHING()

#define AOP_TRUNCATED_PAGE		0x80001
#define MSG_PROBE			0x10
#define PAGE_KERNEL			IGNORED

#define DISCARD_FL_WAIT			IGNORED

#define ioc_task_link(ctx)		DO_NOTHING()

#define ENABLE_CLUSTERING		1   /* nonzero */

#endif	/* USERMODE_LIB_H */
