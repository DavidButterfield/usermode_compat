/* usermode_lib.h
 * Shim for partial emulation/stubbing of selected Linux kernel functions in usermode
 * Copyright 2015 - 2016 David A. Butterfield
 *
 * This is not intended to be #included from code that was written to run in usermode
 *
 * Note that the functions here are implemented around the (apparent) semantics required by
 * particular kernel code of interest -- so they are not likely to conform to the full behavior
 * of the originals, which in most cases have not been consulted to validate these (XXX TODO)
 */
#ifndef USERMODE_LIB_H
#define USERMODE_LIB_H
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <search.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <byteswap.h>
#include <asm/bitsperlong.h>

#include <linux/sysinfo.h>
extern int sysinfo (struct sysinfo *__info);

/* Kernel code doesn't follow the __BYTE_ORDER convention */
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

#include "UMC_kernel.h"	    /* a few random definitions from kernel headers */

#ifdef __x86_64__

 #define cpu_to_le64(x)			(x)
 #define le64_to_cpu(x)			(x)
 #define cpu_to_le32(x)			(x)
 #define le32_to_cpu(x)			(x)
 #define cpu_to_le16(x)			(x)
 #define le16_to_cpu(x)			(x)

 #define get_unaligned(p)		(*(p))
 #define get_unaligned_le16(p)		(*(uint16_t *)(p))
 #define get_unaligned_le32(p)		(*(uint32_t *)(p))
 #define get_unaligned_le64(p)		(*(uint64_t *)(p))

 #define put_unaligned(v, p)		(*(p) = (v)) 
 #define put_unaligned_le16(v, p)	(*(uint16_t *)(p) = (uint16_t)(v)) 
 #define put_unaligned_le32(v, p)	(*(uint32_t *)(p) = (uint32_t)(v)) 
 #define put_unaligned_le64(v, p)	(*(uint64_t *)(p) = (uint64_t)(v)) 

 #define cpu_to_be64(x)			__builtin_bswap64(x)
 #define be64_to_cpu(x)			__builtin_bswap64(x)
 #define cpu_to_be32(x)			__builtin_bswap32(x)
 #define be32_to_cpu(x)			__builtin_bswap32(x)
 #define cpu_to_be16(x)			__builtin_bswap16(x)
 #define be16_to_cpu(x)			__builtin_bswap16(x)

 #define get_unaligned_be16(p)		__builtin_bswap16(*(uint16_t *)(p))
 #define get_unaligned_be32(p)		__builtin_bswap32(*(uint32_t *)(p))
 #define get_unaligned_be64(p)		__builtin_bswap64(*(uint64_t *)(p))

 #define put_unaligned_be16(v, p)	(*(uint16_t *)(p) = __builtin_bswap16((uint16_t)(v))) 
 #define put_unaligned_be32(v, p)	(*(uint32_t *)(p) = __builtin_bswap32((uint32_t)(v))) 
 #define put_unaligned_be64(v, p)	(*(uint64_t *)(p) = __builtin_bswap64((uint64_t)(v))) 

#else
 #warning usermode_lib shim has been compiled on x86 only -- work required for other arch
#endif

/* Qualify a pointer so that its target is treated as volatile */
#define _VOLATIZE(ptr)			((volatile const typeof(ptr))(ptr))
#define WRITE_ONCE(x, val)		(*_VOLATIZE(&(x)) = (val))
#define READ_ONCE(x)			(*_VOLATIZE(&(x)))
#define	ACCESS_ONCE(x)			READ_ONCE(x)

/* Include a few real kernel files */
#include "UMC/linux/export.h"
#include "UMC/linux/list.h"

/* This file (usermode_lib.h) contains the main shim implementation for emulation of
 * kernel services, using GNU C (usermode) library calls, definitions in the header
 * files above, and/or the system services defined in sys_service.h
 */
#include "sys_service.h"    /* system services: event threads, polling, memory, time, etc */
#include "sys_debug.h"	    /* assert, verify, expect, panic, warn, etc */

/* Let "kernel backport" code take us back as far as 2.6.24; then fill in from there
								    (your backport may vary) */
#define LINUX_VERSION_CODE		KERNEL_VERSION(2, 6, 24)

/***** Misc *****/

/* Symbol construction */
#define _CONCAT(a, b)                   __CONCAT__(a, b)
#define __CONCAT__(a, b)                a##b

/* Compile-time assertion */
#define BUILD_BUG_ON(cond)		assert_static(!(cond))

/* For stubbing out unused functions, macro arguments, etc */
#define IGNORED				0
#define DO_NOTHING(USED...)		do { USED; } while (0)
#define FATAL(fn, ret...)		(sys_panic("REACHED UNIMPLEMENTED FUNCTION %s", #fn), ##ret)

/* Avoid compiler warnings for stubbed-out macro arguments */
#define _USE(x)				({ if (0 && (uintptr_t)(x)==0) {}; 0; })

/* Optimizer hints */
#define __pure				__attribute__((__pure__))
#define __unused			__attribute__((__unused__))
#define __noreturn			__attribute__((__noreturn__))
#define __must_check			__attribute__((__warn_unused_result__))
#define __aligned(align)		__attribute__((__aligned__(align)))
#define __packed			__attribute__((__packed__))
#define __printf(F, A)			__attribute__((__format__(printf,F,A)))

#define __used				/* */
#define __visible			/* */
#define __init				/* */
#define __exit				/* */
#define __acquires(lock)		/* */
#define __releases(lock)		/* */
#define __force				/* */
#define __user				/* */
#define __iomem				/* */

#define offsetof(TYPE, MEMBER)		__builtin_offsetof(TYPE, MEMBER)

#define container_of(ptr, type, member) \
	    ({			\
		typeof( ((type *)0)->member ) *__mptr = (ptr); /* validate type */ \
		(type *)( (char *)__mptr - offsetof(type,member) ); \
	    })

#define ARRAY_SIZE(a)			((int)(sizeof(a)/sizeof((a)[0])))

/* Remove the "const" qualifier from a pointer --
			    Places where this is needed should be fixed XXX */
static inline void *
_unconstify(void const * cvp)
{
    union { void * vp; void const * cvp; } p;
    p.cvp = cvp;
    return p.vp;
}

extern size_t UMC_size_t_JUNK;		/* for avoiding unused-value gcc warnings */

#define __CACHE_LINE_BYTES		64  /* close enough */
#define ____cacheline_aligned		__attribute__((aligned(__CACHE_LINE_BYTES)))
#define ____cacheline_aligned_in_smp	____cacheline_aligned

typedef uint64_t __attribute__((aligned(8))) aligned_u64;

#define ilog2(v)	    (likely((v) > 0) ? 63 - __builtin_clzl((uint64_t)(v)) : -1)

#define hash_long(val, ORDER)		( (val) % ( 1 << (ORDER) ) )

static inline uint64_t
_ROUNDDOWN(uint64_t const v, uint64_t const q) { return v / q * q; }

static inline uint64_t
_ROUNDUP(uint64_t const v, uint64_t const q) { return (v + q - 1) / q * q; }

/* Translate an rc/errno system-call return into a kernel-style -errno return */
#define UMC_kernelize(callret...) \
	    ({ int u_rc = (callret); unlikely(u_rc < 0) ? -errno : u_rc; })
#define PTR_ERR(ptr)			((uintptr_t)(ptr))
#define ERR_PTR(err)			((void *)(uintptr_t)(err))
#define IS_ERR(ptr)			unlikely((unsigned long)(ptr) > (unsigned long)(-4096))

#define	ERESTARTSYS			EINTR
#define ENOTSUPP			ENOTSUP

#define kvec				iovec

/* The kernel implementation requires HZ to be fixed at compile-time */
#define HZ				1000U
#define jiffies				( sys_time_now() / (sys_time_hz()/HZ) )

#define jiffies_to_sys_time(j)		( (unsigned long)(j) * (sys_time_hz()/HZ) )
#define jiffies_of_sys_time(t)		( (unsigned long)(t) / (sys_time_hz()/HZ) )

#define time_after(x, y)		((long)((x) - (y)) > 0)
#define time_after_eq(x, y)		((long)((x) - (y)) >= 0)
#define time_before(x, y)		time_after((y), (x))

#define msleep(ms)			usleep((ms) * 1000)

#define simple_strtoul(str, endptr, base)   strtoul((str), (endptr), (base))
#define strict_strtol(str, base, var)	((*var) = strtol((str), NULL, (base)))
#define	strict_strtoll(str, base, var)	((*var) = strtoll((str), NULL, (base)))
#define strict_strtoul(str, base, var)	((*var) = strtoul((str), NULL, (base)))
#define	strict_strtoull(str, base, var) ((*var) = strtoull((str), NULL, (base)))

static inline char *
strnchr(const char * str, size_t strmax, int match)
{
    while (strmax && *str) {
	if (*str == match) return _unconstify(str);
	++str;
	--strmax;
    }
    return NULL;
}

/* Externally-visible entry points for module init/exit functions */

#define module_init(fn)		 extern errno_t _CONCAT(UMC_INIT_, fn)(void); \
					errno_t _CONCAT(UMC_INIT_, fn)(void) { return fn(); }

#define module_exit(fn)		 extern void _CONCAT(UMC_EXIT_, fn)(void); \
					void _CONCAT(UMC_EXIT_, fn)(void) { fn(); }

extern errno_t UMC_init(char *);	/* usermode_lib.c */
extern void UMC_exit(void);

#define _PER_THREAD			__thread
extern _PER_THREAD struct task_struct * current;    /* current thread */

extern struct _irqthread * UMC_irqthread;   /* delivers "softirq" callbacks */

/***** Memory *****/

#ifndef PAGE_SHIFT
#define PAGE_SHIFT			16U	//XXXXXX 12U	/* need not match real kernel */
#endif

#define PAGE_SIZE			(1UL<<PAGE_SHIFT)
#define PAGE_MASK			(~(PAGE_SIZE-1))

static inline void
si_meminfo(struct sysinfo *si)
{
    struct sysinfo si_space;
    int rc = sysinfo(&si_space);
    expect_rc(rc, sysinfo);
    /* Kernel code appears to assume the unit is PAGE_SIZE */
    unsigned int unit = si_space.mem_unit;
    si->totalram = si_space.totalram * unit / PAGE_SIZE;
    si->totalhigh = si_space.totalhigh * unit / PAGE_SIZE;
}

#ifndef PAGE_CACHE_SHIFT
/* In theory this can be different from PAGE_SHIFT, but I'm not sure all the code is correct */
#define PAGE_CACHE_SHIFT		PAGE_SHIFT
#endif

#define PAGE_CACHE_SIZE			(1UL<<PAGE_CACHE_SHIFT)
#define PAGE_CACHE_MASK			(~(PAGE_CACHE_SIZE-1))

#ifndef KMEM_CACHE_ALIGN_MIN
#define KMEM_CACHE_ALIGN_MIN		__CACHE_LINE_BYTES
#endif

#ifndef KMEM_CACHE_ALIGN
#define KMEM_CACHE_ALIGN(size)		((size) >= PAGE_SIZE ? PAGE_SIZE : \
					 (size) >= 512 ? 512 : KMEM_CACHE_ALIGN_MIN)
#endif

typedef unsigned int			gfp_t;	/* kalloc flags argument type (ignored) */

#define PAGE_ALIGN(addr)		(_ROUNDUP((uintptr_t)(addr), PAGE_SIZE))

#define kmem_cache			sys_buf_cache

#define kmem_cache_create(name, size, align, gfp, constructor) ({ \
	    assert_eq(constructor, NULL); /* XXX kmem_cache constuctor unsupported */ \
	    sys_buf_cache_create((name), (size), (align) ? :  __CACHE_LINE_BYTES );  })

#define KMEM_CACHE(s, gfp) \
	    kmem_cache_create(#s, sizeof(struct s), KMEM_CACHE_ALIGN_MIN, (gfp), 0)

#define kmem_cache_destroy(cache)	sys_buf_cache_destroy(cache)

#define kmem_cache_alloc(cache, gfp)	(_USE(gfp), (void *)sys_buf_alloc(cache))
#define kmem_cache_zalloc(cache, gfp)	(_USE(gfp), (void *)sys_buf_zalloc(cache))
#define kmem_cache_free(cache, ptr)	sys_buf_drop((sys_buf_t)(ptr))

typedef	struct mempool {
    struct kmem_cache	  * cache;
    bool		    cache_owned;
} mempool_t;

#define mempool_alloc_slab		NULL
#define mempool_free_slab		NULL

#define mempool_destroy(mempool) \
	    ({  errno_t _ret = E_OK; \
		if ((mempool)->cache_owned) { \
		    assert((mempool)->cache); \
		    _ret = kmem_cache_destroy((mempool)->cache); \
		} \
		vfree(mempool); \
		_ret; \
	    })

#define mempool_create(min_nr, alloc_fn, free_fn, kcache) \
	    ({  assert_eq((alloc_fn), NULL); /* unused */ \
		assert_eq((free_fn), NULL); \
		mempool_t * _ret = vzalloc(sizeof(*_ret)); \
		_ret->cache = (kcache); \
		_ret; \
	    })

#define mempool_create_kmalloc_pool(min_nr, size) \
	    ({	mempool_t * _ret = mempool_create((min_nr), IGNORED, IGNORED, \
					    kmem_cache_create("mempool", (size), \
					    KMEM_CACHE_ALIGN(size), IGNORED, IGNORED)); \
		_ret->cache_owned = true; \
		_ret; \
	     })

#define mempool_alloc(mempool, gfp)	kmem_cache_alloc((mempool)->cache, (gfp))
#define mempool_free(entry, mempool)	kmem_cache_free((mempool)->cache, (entry))

#define kmem_cache_alloc_node(cache, gfp, nodeid) (_USE(nodeid), kmem_cache_alloc(cache, (gfp)))

#define vmalloc(size)			sys_mem_alloc(size)
#define vzalloc(size)			sys_mem_zalloc(size)
#define vrealloc(oaddr, nsize)		sys_mem_realloc((oaddr), (nsize))
#define vfree(ptr)			sys_mem_free(ptr)

#define kalloc(size, gfp)		(_USE(gfp), vmalloc(size))
#define kzalloc(size, gfp)		(_USE(gfp), vzalloc(size))
#define kzalloc_node(size, gfp, nodeid) (_USE(nodeid), kzalloc((size), (gfp)))


#define krealloc(oaddr, nsize, gfp)	(_USE(gfp), vrealloc((oaddr), (nsize)))
#define kfree(ptr) \
	    do { \
		if (likely(ptr)) vfree(ptr); \
		/* else sys_warning("Attempt to kfree(NULL)"); */ \
	    } while (0)

#define __vmalloc(size, gfp, prot)	kalloc((size), (gfp))
#define kmalloc(size, gfp)		kalloc((size), (gfp))
#define kmalloc_track_caller(size, gfp)	kalloc((size), (gfp))
#define kcalloc(count, size, gfp)	kzalloc((count) * (size), (gfp))

#define kmemdup(addr, len, gfp)		memcpy(kalloc((len), (gfp)), (addr), (len))
#define kstrdup(string, gfp)		kmemdup((string), 1+strlen(string), (gfp))
#define strlcpy(dst, src, size)		(dst[(size)-1] = '\0', strncpy((dst), (src), (size)-1), UMC_size_t_JUNK=strlen(dst))

#define copy_from_user(dst, src, len)	(memcpy((dst), (src), (len)), E_OK)
#define copy_to_user(dst, src, len)	(memcpy((dst), (src), (len)), E_OK)
#define get_user(id, ptr)		(((id) = *(ptr)), E_OK)
#define put_user(val, ptr)		((*(ptr) = (val)), E_OK)

/* These "page" functions actually work on addresses, not struct page */
#define __get_free_page(gfp)		kalloc(PAGE_SIZE, (gfp))
#define get_zeroed_page(gfp)		kzalloc(PAGE_SIZE, (gfp))
#define free_page(addr)			kfree((void *)(addr))
#define copy_page(dst, src)		memcpy((dst), (src), PAGE_SIZE)

/* our "page *" points directly to a (userspace virtual) memory address */
struct page { char bytes[PAGE_SIZE]; };

#define page_address(page)		((void *)(page))
#define virt_to_page(addr)		((struct page *)((uintptr_t)(addr) &  PAGE_MASK))
#define virt_to_page_ofs(addr)		((size_t)       ((uintptr_t)(addr) & ~PAGE_MASK))
#define page_to_pfn(page)		((uintptr_t)page_address(page) >> PAGE_SHIFT)

#define alloc_page(gfp)			((struct page *)kalloc(PAGE_SIZE, (gfp)))
#define alloc_pages(gfp, order)		((struct page *)kalloc((1<<(order)) * PAGE_SIZE, (gfp)))
#define __free_page(page)		kfree(page_address(page))
#define __free_pages(page, order)	kfree(page_address(page))
#define nth_page(page, n)		((void *)(page) + (n)*PAGE_SIZE)

#define clear_page(page)		memset(page_address(page), 0, PAGE_SIZE)

#define kmap(page)			(page_address(page))
#define kmap_atomic(page, km_type)	(page_address(page))
#define kunmap(page)			DO_NOTHING()
#define kunmap_atomic(page, obsolete)	DO_NOTHING()

/* Return binary order of magnitude of val, where PAGE_SIZE is (the high-end of) order zero */
static inline uint32_t
get_order(unsigned long val)
{
    unsigned long scaled_val = (val - 1) / PAGE_SIZE;
    return scaled_val ? 1 + ilog2(scaled_val) : 0;
}

/***** Scatter/gather *****/

struct scatterlist {
    unsigned long   page_link;	/* may contain pointer to struct page or struct scatterlist */
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

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
                               unsigned int len, unsigned int offset)
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

/***** Bitmap (non-atomic) *****/

#define BITMAP_MASK(nbits) (((nbits) == BITS_PER_LONG) ? ~0UL : (1UL << (nbits)) - 1)

static inline void
bitmap_fill(unsigned long *dst, int nbits)
{
	assert_be(nbits, BITS_PER_LONG);
	dst[0] = BITMAP_MASK(nbits);
}

static inline void
bitmap_copy(unsigned long *dst, const unsigned long *src, int nbits)
{
	assert_be(nbits, BITS_PER_LONG);
	*dst = *src;
}

static inline int
bitmap_equal(const unsigned long *src1, const unsigned long *src2, int nbits)
{
	assert_be(nbits, BITS_PER_LONG);
	return ! ((*src1 ^ *src2) & BITMAP_MASK(nbits));
}

static inline unsigned int
find_next_bit(const unsigned long *addr, unsigned long nbits, int startbit)
{
    assert_be(nbits, BITS_PER_LONG);
    assert_le(startbit, (long)nbits - 1);
    unsigned int bn;
    unsigned long mask;
    for (bn = startbit, mask = 1UL << startbit; bn < nbits; bn++, mask = mask << 1) {
	if (*addr & mask) return bn;
    }
    return nbits;
}

#define __set_bit(bit, ptr)		(assert_be(bit, BITS_PER_LONG-1), *(ptr) |=  (1ull<<(bit)))

/***** Formatting and logging *****/

#define scnprintf(buf, bufsize, fmtargs...) (snprintf((buf), (bufsize), fmtargs), UMC_size_t_JUNK=strlen(buf))

#define kasprintf(gfp, fmt, args...)	sys_sprintf(fmt, ##args)
#define kvasprintf(gfp, fmt, va)	sys_vsprintf(fmt, va)
#define dump_stack()			sys_backtrace("kernel-code call to dump_stack()")
#define panic(fmtargs...)		sys_panic(fmtargs)
#define printk(fmtargs...)		sys_eprintf(fmtargs)
#define vprintk(fmt, va)		sys_veprintf(fmt, va)

#define KERN_CONT			""
#define KERN_INFO			"INFO: "
#define KERN_DEBUG			"DEBUG: "
#define KERN_WARNING			"WARNING: "
#define KERN_ERR			"ERROR: "
#define KERN_CRIT			"CRITICAL: "
#define KERN_EMERG			"EMERGENCY: "

#define KERN_LOC_FIELDS			gettid(), __func__, __LINE__, __FILE__
#define KERN_LOC_FMT			"[%u] %s:%u (%s):"
#define pr_fmt(fmt)			fmt

/* Unconditional */
#define BUG()				panic("BUG at "KERN_LOC_FMT"\n", KERN_LOC_FIELDS)
#define pr_debug(fmtargs...)		printk(KERN_DEBUG fmtargs)

/* NB: Some callers of BUG_ON and WARN_ON rely on the result and/or side-effects of the
 * expression being tested as part of program functionality -- which means BUG_ON (et al)
 * must remain as "verify" rather than "assert" so as to be compiled into all builds.
 */
#define BUG_ON(cond, fmtargs...)	verify(!(cond), ##fmtargs)

#define WARN(cond, fmtargs...)		_WARN_ON((cond), ""fmtargs)
#define WARN_ON(cond, fmtargs...)	_WARN_ON((cond), ""fmtargs)
#define _WARN_ON(cond, fmt, args...) \
	    ({ \
		uintptr_t _ret = (cond) != 0;    /* evaluate cond exactly once */ \
		if (unlikely(_ret != 0)) { \
		    printk(KERN_WARNING"%s %ld/0x%lx "fmt"\n", #cond, _ret, _ret, ##args); \
		} \
		_ret; \
	    })

#define ONCE_OR_TWICE	10  /* up to this many of a warning each thread */

#define WARN_ON_ONCE(cond)		WARN_ONCE(cond)
#define WARN_ONCE(cond, fmtargs...)	_WARN_ONCE((cond), ""fmtargs)
#define _WARN_ONCE(cond, fmt, args...) \
	    ({ \
		uintptr_t _ret = (cond);    /* evaluate cond exactly once */ \
		if (unlikely(_ret != 0)) { \
		    static _PER_THREAD int _been_here = 0; \
		    if (unlikely(_been_here < ONCE_OR_TWICE)) { \
			++_been_here; \
		        printk(KERN_WARNING"[%u/%u] %s %ld/0x%lx "fmt"\n", \
			       _been_here, ONCE_OR_TWICE, \
			       #cond, _ret, _ret, ##args); \
		    } \
		} \
		_ret; \
	    })

/***** Barriers, Atomics, Locking *****/

#define __barrier()			__sync_synchronize()
#define smp_mb()			__barrier()
#define smp_rmb()			__barrier()
#define smp_wmb()			__barrier()

/* For some reason the kernel omits declaring its atomic types as volatile, resulting
 * in the need to additionally call auxiliary compiler-barrier functions there.
 *
 * Here in the usermode library, the CPU barrier is provided by the __sync_fetch_and_*()
 * builtin function, and the compiler barrier by virtue of the content of the atomic_t
 * being declared volatile.
 */
#define smp_mb__after_set_bit()		DO_NOTHING()
#define smp_mb__before_clear_bit()	DO_NOTHING()
#define	smp_mb__after_clear_bit()	DO_NOTHING()
#define	smp_mb__after_atomic()		DO_NOTHING()
#define	smp_mb__before_atomic()		DO_NOTHING()
#define	smp_mb__before_atomic_dec()	DO_NOTHING()
#define	smp_mb__after_atomic_dec()	DO_NOTHING()
#define	smp_mb__after_atomic_inc()	DO_NOTHING()

typedef struct { int32_t volatile i; }  atomic_t;   /* must be signed */
#define ATOMIC_INIT(n)			((atomic_t){ .i = (n) })
					//XXXX Figure out which of these barriers isn't needed
#define atomic_get(ptr)			({ __barrier(); int32_t __ret = (ptr)->i; __barrier(); __ret; })
#define atomic_set(ptr, val)		do { __barrier(); (ptr)->i = (val); __barrier(); } while (0)

/* Bitwise atomics return the OLD value */
#define atomic_or(n, ptr)		__sync_fetch_and_or( &(ptr)->i, (n))
#define atomic_and(n, ptr)		__sync_fetch_and_and(&(ptr)->i, (n))

/* Arithmetic atomics return the NEW value */
#define atomic_add_return(n, ptr)	__sync_add_and_fetch(&(ptr)->i, (n))
#define atomic_sub_return(n, ptr)	__sync_sub_and_fetch(&(ptr)->i, (n))
#define atomic_inc_return(ptr)		atomic_add(1, (ptr))
#define atomic_dec_return(ptr)		atomic_sub(1, (ptr))

#define atomic_read(ptr)		atomic_get(ptr)
#define atomic_add(n, ptr)		atomic_add_return((n), (ptr))
#define atomic_sub(n, ptr)		atomic_sub_return((n), (ptr))
#define atomic_inc(ptr)			atomic_inc_return(ptr)
#define atomic_dec(ptr)			atomic_dec_return(ptr)

#define atomic_dec_and_test(ptr)	(!atomic_dec_return(ptr)) /* true if result *IS* zero */

static inline bool
_atomic_cas(atomic_t * atomic, int32_t const expected, int32_t const newval)
{
    return __sync_bool_compare_and_swap(&atomic->i, expected, newval);
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

/* These appear to operate on regular longs, not declared atomic, yet expecting atomicity */
/* For convenience of test_and_set_bit, returns the OLD value of the entire long holding the bit */
//XXX Spanning multiple longs in a long bitmap is not implemented
#define set_bit(bitno, ptr)   ( assert_be(bitno, BITS_PER_LONG-1), \
			      __sync_fetch_and_or(_VOLATIZE(&(ptr)[0]),  (1ull<<(bitno))) )
#define clear_bit(bitno, ptr) ( assert_be(bitno, BITS_PER_LONG-1), \
			      __sync_fetch_and_and(_VOLATIZE(&(ptr)[0]), ~(1ull<<(bitno))) )
#define test_bit(bitno, ptr)  ( (*_VOLATIZE(ptr) & (1ull<<(bitno))) != 0 )

/* Return true if bit was previously set, false if not */
#define test_and_set_bit(bitno, ptr) unlikely((set_bit((bitno), (ptr)) & (1UL << (bitno))) != 0)

/*** kref ***/

struct kref { atomic_t refcount; };

#define kref_init(kref)			atomic_set(&(kref)->refcount, 1)

#define kref_get(kref) \
	    do { uint32_t nrefs = atomic_inc_return(&(kref)->refcount); \
		 assert_ae(nrefs, 2); \
	    } while (0)

#define kref_put(kref, destructor) \
	    do { assert(destructor); \
		 if (atomic_dec_and_test(&(kref)->refcount)) destructor(kref); \
	    } while (0)

/*** spin locks ***/

#define UMC_LOCK_CHECKS	    true	/* do lock checks in all builds */

#if defined(__i386__) || defined(__x86_64__)
  /* Avoid clogging CPU pipeline with lock fetches for several times around a spinloop */
  #ifdef NVALGRIND
    #define _SPINWAITING()		__builtin_ia32_pause()
  #else
    #include "valgrind.h"
    /* There seems to be some problem with valgrind looping with this instruction XXX */
    #define _SPINWAITING()   do { if (!RUNNING_ON_VALGRIND) __builtin_ia32_pause(); } while (0)
  #endif
#else
  #define _SPINWAITING()		DO_NOTHING()
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

#define RW_LOCK_UNLOCKED(rwname)	{ .count = { _RW_LOCK_WR_COUNT }, .name = rwname }
#define DEFINE_RWLOCK(rw)		struct rwlock rw = RW_LOCK_UNLOCKED(#rw)
#define rwlock_init(rw)			(*(rw) = (rwlock_t)RW_LOCK_UNLOCKED(#rw))

static inline void
rwlock_assert_writer(rwlock_t * const rw)
{
#ifdef UMC_LOCK_CHECKS
    verify_le(atomic_read(&rw->count), 0, "Writer not exclusive??");
    verify_eq(sys_thread_current(), rw->owner, "%s expected to own lock '%s' owned instead by %s",
	      sys_thread_name(sys_thread_current()), rw->name, sys_thread_name(rw->owner));
#endif
}

/* Returns E_OK if ntake acquired, else -EBUSY (zero count taken) */
static inline errno_t
rwlock_take_try(rwlock_t * rw, uint32_t ntake)
{
    /* Try to take the requested count */
    if (unlikely(atomic_sub_return(ntake, &rw->count) < 0)) {
	/* Overdraft -- insufficient count available to satisfy "take" request */
	atomic_add(ntake, &rw->count);	/* give back our overdraft of rw->count */
#ifdef UMC_LOCK_CHECKS
	verify(rw->owner != sys_thread_current(),
	       "Thread attempts to acquire a spinlock it already holds");
#endif
	return -EBUSY;
    }
    /* Successfully took (ntake) from lock available count */
#ifdef UMC_LOCK_CHECKS
    verify_eq(rw->owner, NULL);	    /* we got it, so nobody else better own it exclusively */
    if (ntake > _RW_LOCK_RD_COUNT) {
	/* We're not merely reading -- record as exclusive owner */
	rw->owner = sys_thread_current();
    }
#endif
#if 0
    trace("'%s' (%u) takes %u for %s from spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  ntake, ntake > _RW_LOCK_RD_COUNT ? "WRITE" : "READ", rw->name, rw);
#endif
    return E_OK;
}

#define read_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_RD_COUNT)
#define write_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_WR_COUNT)

#define read_lock(rw)			while (read_lock_try(rw) != E_OK) _SPINWAITING()
#define write_lock(rw)			while (write_lock_try(rw) != E_OK) _SPINWAITING()

static inline void
rwlock_drop(rwlock_t * const rw, uint32_t ndrop)
{
#if 0
    trace("'%s' (%u) returns %u (%s) to spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  ndrop, ndrop > _RW_LOCK_RD_COUNT ? "WRITE" : "READ", rw->name, rw);
#endif
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

/* Mutex SPIN lock */
/* Implement using a pthread_mutex and _trylock(), so it can work with pthread_cond_t */
typedef struct spinlock {
    pthread_mutex_t	    plock;
#ifdef UMC_LOCK_CHECKS
    sys_thread_t   volatile owner;
#endif
    sstring_t		    name;
} spinlock_t;				//XXX add some spinlock stats

#define SPINLOCK_UNLOCKED(lock)		{ .plock = PTHREAD_MUTEX_INITIALIZER, .name = lock }
#define DEFINE_SPINLOCK(lock)		spinlock_t lock = SPINLOCK_UNLOCKED(#lock)
#define spin_lock_init(lock)		(*(lock) = (spinlock_t)SPINLOCK_UNLOCKED(#lock))

static inline void
spin_lock_assert_holding(spinlock_t * const lock)
{
#ifdef UMC_LOCK_CHECKS
    assert(lock);
    verify_eq(sys_thread_current(), lock->owner, "%s expected to own lock '%s' owned instead by %s",
	      sys_thread_name(sys_thread_current()), lock->name, sys_thread_name(lock->owner));
#endif
}

#ifdef UMC_LOCK_CHECKS
#define SPINLOCK_CLAIM(lock)	verify_eq((lock)->owner, NULL); (lock)->owner = sys_thread_current();
#define SPINLOCK_DISCLAIM(lock)	spin_lock_assert_holding(lock); (lock)->owner = NULL;
#else
#define SPINLOCK_CLAIM(lock)	DO_NOTHING()
#define SPINLOCK_DISCLAIM(lock)	DO_NOTHING()
#endif

/* Returns E_OK if lock acquired, else -EBUSY */
static inline errno_t
spin_lock_try(spinlock_t * lock)
{
    if (unlikely(pthread_mutex_trylock(&lock->plock) != 0)) {
#ifdef UMC_LOCK_CHECKS
	verify(lock->owner != sys_thread_current(),
	       "Thread %d ('%s') attempts to acquire a spinlock '%s' (%p) it already holds (%p)",
	       gettid(), sys_thread_name(sys_thread_current()), lock->name, lock, lock->owner);
#endif
	return -EBUSY;
    }
    /* Successfully acquired lock */
    SPINLOCK_CLAIM(lock);
#if 0
    trace("'%s' (%u) takes spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  lock->name, lock);
#endif
    return E_OK;
}

static inline void
spin_lock(spinlock_t * lock)
{
    while (spin_lock_try(lock) != E_OK) _SPINWAITING();
}

static inline void
spin_unlock(spinlock_t * const lock)
{
#if 0
    trace("'%s' (%u) drops spinlock %s at %p",
	  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
	  rw->name, rw);
#endif
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

#define MUTEX_UNLOCKED(mname)		((struct mutex){ .lock = PTHREAD_MUTEX_INITIALIZER, .name = mname })
#define DEFINE_MUTEX(m)			struct mutex m = MUTEX_UNLOCKED(#m)
#define mutex_init(m)			do { *(m) = MUTEX_UNLOCKED(#m); } while (0)

static inline void
mutex_assert_holding(mutex_t * m)
{
#ifdef UMC_LOCK_CHECKS
    verify_eq(sys_thread_current(), m->owner, "%s expected to own mutex '%s' owned instead by %s",
	      sys_thread_name(sys_thread_current()), m->name, sys_thread_name(m->owner));
#endif
}

/* Try to acquire a mutex lock -- returns E_OK if lock acquired, -EBUSY if not */
#define mutex_trylock(m)		_mutex_trylock((m), FL_STR)
static inline errno_t
_mutex_trylock(mutex_t * m, sstring_t whence)
{
    if (unlikely(pthread_mutex_trylock(&m->lock))) {
	/* Can't get the lock because it is held by somebody */
#ifdef UMC_LOCK_CHECKS
	verify(m->owner != sys_thread_current(),
	       "Thread attempts to acquire a mutex it already holds");
#endif
	return -EBUSY;
    }
#ifdef UMC_LOCK_CHECKS
    verify_eq(m->owner, NULL);
    m->owner = sys_thread_current();
#endif
    m->whence = whence;
#if 0
    trace("'%s' (%u) at %s acquires mutex '%s' (%p)",
	  sys_thread_name(m->owner), sys_thread_num(m->owner), whence, m->name, m);
#endif
    return E_OK;
}

/* Acquire a mutex lock -- attempt to avoid a context switch when wait time is short */
#define mutex_lock(m)			_mutex_lock((m), FL_STR)
static inline void
_mutex_lock(mutex_t * m, sstring_t whence)
{
    #define MUTEX_SPINS 100	/* Try this many spins before resorting to context switch */
    uint32_t spins = MUTEX_SPINS;
    while (--spins) {
	if (likely(_mutex_trylock(m, whence) == E_OK)) {
	    return;	/* got the lock */
	}
	_SPINWAITING();
    }

    /* We exhausted the time we're willing to spinwait -- give up the CPU */
#if 0
#if !OPTIMIZED
    sys_time_t const t_start = sys_time_now();
#endif
#endif
    /*** SLEEP ***/
    pthread_mutex_lock(&m->lock);

    /*** AWAKE ***/
#ifdef UMC_LOCK_CHECKS
    verify_eq(m->owner, NULL);
    m->owner = sys_thread_current();
#endif

#if 0
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

#define mutex_lock_interruptible(m)	(mutex_lock(m), E_OK)

static inline void
mutex_unlock(mutex_t * m)
{
    mutex_assert_holding(m);
#if 0
    trace("'%s' (%u) drops mutex '%s' (%p)",
	  sys_thread_name(m->owner), sys_thread_num(m->owner), m->name, m);
#endif
    m->owner = NULL;
    pthread_mutex_unlock(&m->lock);
}

/* Use of this function is inherently racy */
static inline bool
mutex_is_locked(mutex_t * const m)
{
    if (unlikely(mutex_trylock(m) != E_OK)) {
	return true;	/* we couldn't get the mutex, therefore it is locked */
    }
    mutex_unlock(m);    /* unlock the mutex we just locked to test it */
    return false;	/* We got the mutex, therefore it was not locked */
}

/* Note: this macro gets invoked on both mutex locks and spin locks */
#define lockdep_assert_held(m)		assert_eq(sys_thread_current(), (m)->owner)

/***** Tasks and Scheduling *****/

#define raw_smp_processor_id()		sched_getcpu()	/* very fast nowadays */
#define smp_processor_id()		sched_getcpu()

#define	NR_CPUS				BITS_PER_LONG	//XXX

#if NR_CPUS > BITS_PER_LONG
#error Additional work required to support more than 64 CPUs (uses a single long as mask)
#endif

#define nr_cpu_ids			NR_CPUS
typedef struct { unsigned long bits[NR_CPUS/BITS_PER_LONG]; } cpumask_t;

#define cpumask_clear(cpumask)		memset((cpumask), 0, sizeof(*(cpumask)))

#define cpumask_scnprintf(buf, bufsize, mask)	\
	    (snprintf((buf), (bufsize), "<0x%016x>", mask.bits[0]), UMC_size_t_JUNK=strlen(buf))

static inline int
num_online_cpus(void)
{
    cpu_set_t cpuset;
    //XXX FIX:  this is supposed to be system CPUs, not this thread's
    int rc = sched_getaffinity(getpid(), sizeof(cpuset), &cpuset);
    if (rc) return 0;
    return CPU_COUNT(&cpuset);
}

#define NUMA_NO_NODE			(-1)
#define cpu_to_node(cpu)		(0)
#define cpu_online(cpu)			(1)

#define in_softirq()			false // (sys_event_task_current() != NULL)
#define in_atomic()			false   //XXX OK?
#define in_irq()			false	/* never in hardware interrupt */
#define in_interrupt()			(in_irq() || in_softirq())

/*** Wait queues -- wait (if necessary) for a condition to be true ***/

/* The actual queue itself is managed by pthreads, not visible here */
//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
typedef struct wait_queue_head {
    spinlock_t		    lock_nolock;    /* synchronizes pcond when non-locked wait */
    pthread_cond_t	    pcond;	    /* sleep awaiting condition change */
    bool	   volatile initialized;
    bool		    is_exclusive;   /* validate XXX limitation assumption */
} wait_queue_head_t;

/* The pcond has to be initialized at runtime */
#define WAIT_QUEUE_HEAD_INIT(name)	(struct wait_queue_head){ \
					   .lock_nolock = SPINLOCK_UNLOCKED(#name), \
					   /* .pcond = PTHREAD_COND_INITIALIZER, */ \
					   .initialized = false} \

#define DECLARE_WAIT_QUEUE_HEAD(name)	wait_queue_head_t name = WAIT_QUEUE_HEAD_INIT(name)

/* init_waitqueue_head is suitable for initializing dynamic waitqueues */
#define init_waitqueue_head(WAITQ)  /* before exposing them to the view of other threads */ \
	    do { \
		record_zero(WAITQ); \
		spin_lock_init(&(WAITQ)->lock_nolock); \
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
		spin_lock(&(WAITQ)->lock_nolock); \
		if (!(WAITQ)->initialized) { \
		    pthread_condattr_t attr; \
		    pthread_condattr_init(&attr); \
		    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
		    pthread_cond_init(&(WAITQ)->pcond, &attr); \
		    pthread_condattr_destroy(&attr); \
		    (WAITQ)->initialized = true; \
		} \
		spin_unlock(&(WAITQ)->lock_nolock); \
	    } while (0)

/* Limitation: locked waits are always exclusive, non-locked always non-exclusive.
 *
 * The WAITQ_CHECK_INTERVAL is a hack to allow checking for unwoken events like
 * kthread_should_stop, without having to implement additional queuing for waiters.  We'll wake
 * up to recheck the COND each time interval, even if no wakeup has been sent; so that interval
 * is the maximum delay between an unwoken event and the thread noticing it.  (This is only for
 * infrequent cases like shutting down threads; normally when the condition changes the thread
 * is sent an explicit wake_up.)
 */
#define WAITQ_CHECK_INTERVAL	sys_time_delta_of_ms(350)   /* kthread_stop check interval */

/*  If INNERLOCKP != NULL, lock acquisition order is LOCKP, INNERLOCKP;
 *  The pcond_wait call drops the (outer or solitary) LOCKP
 */
#define _wait_event_locked_timeout(WAITQ, COND, LOCKP, INNERLOCKP, _t_expire) \
	    ({ \
		verify((WAITQ).initialized); \
		spin_lock_assert_holding(LOCKP); \
		if (INNERLOCKP) spin_lock_assert_holding(INNERLOCKP); \
		sys_time_t const _t_end = (_t_expire); /* evaluate _t_expire only once */ \
		expect_gt(_t_end, sys_time_now()); \
		if (unlikely(!(COND))) { \
		    errno_t _err; \
		    struct timespec const ts_end = { \
					    .tv_sec = sys_time_delta_to_sec(_t_end), \
					    .tv_nsec = sys_time_delta_mod_sec(_t_end)  }; \
		    while (!(COND)) { \
			if (unlikely(time_after_eq(sys_time_now(), _t_end))) break; \
			\
			if (INNERLOCKP) spin_unlock(INNERLOCKP); \
			SPINLOCK_DISCLAIM(LOCKP);    /* cond_wait drops LOCK */ \
			_err = pthread_cond_timedwait(&(WAITQ).pcond, &(LOCKP)->plock, &ts_end);\
			SPINLOCK_CLAIM(LOCKP);	    /* cond_wait reacquires LOCK */ \
			if (INNERLOCKP) spin_lock(INNERLOCKP); \
			if (likely(_err != ETIMEDOUT)) \
			    expect_noerr(_err, "pthread_cond_timedwait"); \
		    } \
		} \
		(likely(COND) ? 1 : 0); \
	    })

/* Caution: these "wait_event" macros use unnatural pass-by-name semantics */

/* Wait Event with exclusive wakeup, NO timeout, and spinlock */
#define wait_event_locked(WAITQ, COND, lock_type, LOCK) \
	    do { \
		assert_eq(spin_##lock_type, spin_lock); \
		if (unlikely(!(WAITQ).initialized)) _init_waitqueue_head(&(WAITQ)); \
		(WAITQ).is_exclusive = true; \
		sys_time_t next_check; \
		do { \
		    next_check = sys_time_now() + WAITQ_CHECK_INTERVAL; \
		} while (!_wait_event_locked_timeout((WAITQ), (COND), \
						     &(LOCK), NULL, next_check)); \
	    } while (0)

/* Wait Event with exclusive wakeup, NO timeout, and TWO spinlocks --
 * Lock acquisition order is LOCK, INNERLOCK
 */
#define wait_event_locked2(WAITQ, COND, LOCK, INNERLOCK) \
	    do { \
		if (unlikely(!(WAITQ).initialized)) _init_waitqueue_head(&(WAITQ)); \
		(WAITQ).is_exclusive = true; \
		sys_time_t next_check; \
		do { \
		    next_check = sys_time_now() + WAITQ_CHECK_INTERVAL; \
		} while (!_wait_event_locked_timeout((WAITQ), (COND), \
						     &(LOCK), &(INNERLOCK), next_check)); \
	    } while (0)

/* Common internal helper for Non-exclusive wakeups */
#define _wait_event_timeout(WAITQ, COND, t_end) \
	    ({ \
		assert(!(WAITQ).is_exclusive, "Mixed waitq exclusivity"); \
		if (unlikely(!(WAITQ).initialized)) _init_waitqueue_head(&(WAITQ)); \
		spin_lock(&(WAITQ).lock_nolock); \
		errno_t const _ret = \
		    _wait_event_locked_timeout((WAITQ), (COND), \
					       &(WAITQ).lock_nolock, NULL, (t_end)); \
		spin_unlock(&(WAITQ).lock_nolock); \
		_ret; \
	    })

/* Non-exclusive wakeup WITH timeout, and periodic checks for kthread_should_stop */
//XXX Limitation: when condition is met, returns 1 instead of the number of ticks remaining
#define wait_event_interruptible_timeout(WAITQ, COND, jdelta) \
	    ({ \
		sys_time_t const t_end = sys_time_now() + jiffies_to_sys_time(jdelta); \
		sys_time_t next_check; \
		do { \
		    if (kthread_should_stop()) break; \
		    sys_time_t now = sys_time_now(); \
		    if (time_after_eq(now, t_end)) break; \
		    if (t_end - now < WAITQ_CHECK_INTERVAL) next_check = t_end; \
		    else next_check = now + WAITQ_CHECK_INTERVAL; \
		} while (!_wait_event_timeout((WAITQ), (COND), next_check)); \
		(likely(COND) ? 1 : 0); \
	    })

/* Non-exclusive wakeup with NO timeout, with periodic checks for kthread_should_stop */
#define wait_event_interruptible(WAITQ, COND) \
	    ({ \
		sys_time_t next_check; \
		do { \
		    if (kthread_should_stop()) break; \
		    next_check = sys_time_now() + WAITQ_CHECK_INTERVAL; \
		} while (!_wait_event_timeout((WAITQ), (COND), next_check)); \
		(likely(COND) ? 1 : 0); \
	    })

/* Non-exclusive wakeup with NO timeout */
#define wait_event(WAITQ, COND) \
	    do { \
		sys_time_t next_check; \
		do { \
		    next_check = sys_time_now() + WAITQ_CHECK_INTERVAL; \
		} while (!_wait_event_timeout((WAITQ), (COND), next_check)); \
	    } while (0)

/* First change the condition being waited on, then call wake_up*() --
 * These may be called with or without holding the associated lock;
 * if called without, the caller is responsible for handling the races.
 */
#define wake_up_one(WAITQ) \
	    do { \
		if (unlikely(!(WAITQ)->initialized)) _init_waitqueue_head(WAITQ); \
		pthread_cond_signal(&(WAITQ)->pcond); \
	    } while (0)

#define wake_up_all(WAITQ) \
	    do { \
		if (unlikely(!(WAITQ)->initialized)) _init_waitqueue_head(WAITQ); \
		pthread_cond_broadcast(&(WAITQ)->pcond); \
	    } while (0)

//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
#define wake_up(WAITQ) \
	    do { \
		if ((WAITQ)->is_exclusive) wake_up_one(WAITQ); \
		else wake_up_all(WAITQ); \
	    } while (0)

/*** Completions ***/

struct completion {
    wait_queue_head_t	    wait;
    atomic_t		    done;
};

#define COMPLETION_INIT(name)	(struct completion){ \
					    .wait = WAIT_QUEUE_HEAD_INIT((name).wait), \
					    .done = { 0 } }

#define DECLARE_COMPLETION(name)	struct completion name = COMPLETION_INIT(name)


#define init_completion(c)		do { init_waitqueue_head(&(c)->wait); \
					     atomic_set(&(c)->done, 0); \
					} while (0)

#define COMPLETION_INITIALIZER_ONSTACK(c)  COMPLETION_INIT(c)

#define DECLARE_COMPLETION_ONSTACK(name) struct completion name; \
					 init_completion(&name)

#define wait_for_completion(c) \
	    do { \
		while (atomic_dec_return(&(c)->done) < 0) { \
		    /* Overdraft -- give it back */ \
		    atomic_inc(&(c)->done); \
		    wait_event((c)->wait, atomic_read(&(c)->done) > 0); \
		} \
	    } while (0)

#define complete(c) \
	    do { atomic_inc(&(c)->done);        wake_up(    &(c)->wait); } while (0)
#define complete_all(c) \
	    do { atomic_set(&(c)->done, 1<<30); wake_up_all(&(c)->wait); } while (0)

/*** kthreads (simulated kernel threads) ***/

/* A kthread is implemented on top of a sys_thread --
 * each kthread's "current" points to that thread's instance of struct task_struct
 */
struct task_struct {
    sys_thread_t	    SYS;	    /* pointer to system thread info */
    errno_t		  (*run_fn)(void *);/* kthread's work function */
    void		  * run_env;	    /* argument to run_fn */
    struct completion	    started;	    /* synchronize thread start */
    struct completion	    stopped;	    /* synchronize thread stop */
    int			    exit_code;
    bool		    affinity_is_set;

    /* kernel code compatibility */
    cpumask_t		    cpus_allowed;
    bool	   volatile should_stop;    /* kthread shutdown signalling */
    sstring_t		    comm;	    /* thread name (string owned) */
    pid_t	            pid;	    /* tid, actually */
    int			    flags;	    /* ignored */
    void		  * io_context;	    /* unused */
    struct mm_struct      * mm;		    /* unused */
};

#define kthread_should_stop()	(current->should_stop)

#define UMC_current_alloc()	((struct task_struct *)vmalloc(sizeof(struct task_struct)))

#define UMC_current_init(task, _SYS, _FN, _ENV, _COMM) \
	    ({ \
		struct task_struct * _t = (task); \
		record_zero(_t); \
		_t->SYS = (_SYS); \
		_t->run_fn = (_FN); \
		_t->run_env = (_ENV); \
		_t->comm = (_COMM); \
		trace("UMC_current_init(%p) from %s comm=%s", _t, FL_STR, _t->comm); \
		_t; \
	    })

#define UMC_current_set(task) \
	    do { \
		struct task_struct * _t = (task); \
		if (_t != NULL) { \
		    assert_eq(current, NULL); \
		    _t->pid = gettid(); \
		} else { \
		    assert(current != NULL); \
		} \
		current = _t; \
	    } while (0)

#define UMC_current_free(task) \
	    do { \
		struct task_struct * _t = (task); \
		trace("UMC_current_free(%p) from %s", _t, FL_STR); \
		kfree(_t->comm); \
		vfree(_t); \
	    } while (0)

/* Returns 1 if the completion occurred, 0 if it timed out */
static inline int
wait_for_completion_timeout(struct completion * c, uint32_t jdelta)
{
    sys_time_t const t_end = sys_time_now() + jiffies_to_sys_time(jdelta);
    sys_time_t now;
    sys_time_t next_check;

    do {
	/* Try to take one completion */
	if (atomic_dec_return(&(c)->done) >= 0) return 1;   /* got one */

	/* Overdraft -- give it back */
	atomic_inc(&(c)->done);

	/* Check whether we should give up trying to get the completion */
	if (kthread_should_stop()) break;
	now = sys_time_now();
	if (time_after_eq(now, t_end)) break;
	if (t_end - now < WAITQ_CHECK_INTERVAL) next_check = t_end;
	else next_check = now + WAITQ_CHECK_INTERVAL;

	(void) _wait_event_timeout(c->wait, atomic_read(&c->done) > 0, next_check);
    } while (1);

    return 0;	/* timed out or interrupted by kthread_should_stop() */
}

extern errno_t UMC_kthread_fn(void * v_task);    /* start function for a new kthread */

/* Create and initialize a kthread structure -- the pthread is not started yet */
#define kthread_create(fn, env, fmtargs...) _kthread_create((fn), (env), sys_sprintf(fmtargs))
static inline struct task_struct *
_kthread_create(errno_t (*fn)(void * env), void * env, string_t name)
{
    pr_debug("Thread %s (%u) creates kthread %s\n",
	     sys_thread_name(sys_thread_current()), gettid(), name);

    struct task_struct * task = UMC_current_alloc();
    init_completion(&task->started);
    init_completion(&task->stopped);

    sys_thread_t thread = sys_thread_alloc(UMC_kthread_fn, task, kstrdup(name, IGNORED));

    /* Ownership of name string passes to the task_struct */
    UMC_current_init(task, thread, fn, env, name);

    task->SYS->cpu_mask = current->SYS->cpu_mask;
    task->SYS->nice = nice(0);
    task->cpus_allowed = current->cpus_allowed;	    //XXX Right?

    return task;
}

#define kthread_create_on_node(fn, env, nodeid, fmtargs...) \
	    (_USE(nodeid), _kthread_create((fn), (env), sys_sprintf(fmtargs)))

/* Start a previously-created kthread -- returns after new process is ready for use */
#define wake_up_process(task)		kthread_start(task)
static inline errno_t
kthread_start(struct task_struct * task)
{
    errno_t const err = sys_thread_start(task->SYS);
    if (err == E_OK) {
	/* Wait for new thread to be ready */
	wait_for_completion(&task->started);
    }
    return err;
}

/* Create and start a kthread */
#define kthread_run(fn, env, fmtargs...) _kthread_run((fn), (env), sys_sprintf(fmtargs))
static inline struct task_struct *
_kthread_run(errno_t (*fn)(void * env), void * env, string_t name)
{
    struct task_struct * task = _kthread_create(fn, env, name);
    assert(task);

    errno_t const err = kthread_start(task);
    if (err != E_OK) {
	/* Failed to start */
	sys_thread_free(task->SYS);
	record_free(task);
	return ERR_PTR(err);
    }

    return task;	    /* started OK */
}

/* The running kthread exits.
 *
 * It looks like each kthread is designed EITHER to exit ON REQUEST using kthread_stop and
 * kthread_should_stop, OR the thread calls do_exit() when it is DONE, without using the
 * kthread_stop mechanism -- but never a combination of both possibilities.  (XXX but unclear)
 *
 * If that's correct, then do_exit needs to free the task_struct... and it isn't clear what the
 * purpose of the rc is supposed to be if no one is going to wait for it... XXX Investigate
 */
static inline void __noreturn
do_exit(int rc)
{
    UMC_current_free(current);
    current = (void *)MEM_ZAP_64;
    sys_thread_exit(rc);
}

/* Marks kthread for exit, waits for it to exit, and returns its exit code */
static inline errno_t
kthread_stop(struct task_struct * task)
{
    task->should_stop = true;
    verify(task != current);

    /* Wait for the thread to exit */
    if (!wait_for_completion_timeout(&task->stopped, 3 * HZ)) {
	/* Too slow -- jab it for a stacktrace */
	sys_warning("kthread_stop of %s (%u) excessive wait -- attempting stacktrace",
		    task->comm, task->pid);
	tkill(task->pid, SIGSTKFLT);
	if (!wait_for_completion_timeout(&task->stopped, 10 * HZ)) {
	    sys_warning("kthread_stop of %s (%u) excessive wait -- giving up",
			task->comm, task->pid);
	    return -EPERM;
	}
    }

    errno_t const ret = task->exit_code;

    sys_thread_free(task->SYS);
    UMC_current_free(task);

    return ret;
}

#define task_pid_vnr(task)		((task)->pid)

/* This can be called on behalf of a new task before the pthread has been created */
#define set_cpus_allowed(task, mask) ( \
	    task->cpus_allowed = (mask), \
	    task->affinity_is_set = true, \
	    (task)->pid \
		? UMC_kernelize(sched_setaffinity(task->pid, sizeof(mask), \
						  (cpu_set_t *)&(task->cpus_allowed))) \
		: E_OK		     )

#define tsk_cpus_allowed(task)		(&(task)->cpus_allowed)

#define set_user_nice(task, niceness)	/* setpriority(PRIO_PROCESS, (task)->pid, (niceness)) */

/*** Event threads (used for timers and "softirq" asynchronous notifications) ***/

struct _irqthread {
    sys_thread_t	    SYS;	    /* pointer to system thread info */
    sys_event_task_t	    event_task;
    struct task_struct    * current;
    struct completion	    started;	    /* synchronize thread start */
    struct completion	    stopped;	    /* synchronize thread stop */
};

extern errno_t UMC_irqthread_fn(void * v_irqthread);

#define irqthread_alloc(fmtargs...) _irqthread_alloc(sys_sprintf(fmtargs))

static inline struct _irqthread *
_irqthread_alloc(string_t name)
{
    pr_debug("Thread %s (%u) creates irqthread %s\n", current->comm, current->pid, name);

    struct _irqthread * ret = record_alloc(ret);
    init_completion(&ret->started);
    init_completion(&ret->stopped);

    ret->SYS = sys_thread_alloc(UMC_irqthread_fn, ret, kstrdup(name, IGNORED));
    ret->SYS->cpu_mask = current->SYS->cpu_mask;
    ret->SYS->nice = nice(0) - 5;	//XXXX TUNE

    /* The thread will deliver into "kernel" code expecting a "current" to be set */
    ret->current = UMC_current_alloc();

    /* Ownership of name string is passed to the task_struct */
    UMC_current_init(ret->current, ret->SYS, (void *)UMC_irqthread_fn, ret, name);

    struct sys_event_task_cfg cfg = {
	.max_polls = SYS_ETASK_MAX_POLLS,
	.max_steps = SYS_ETASK_MAX_STEPS,
    };

    ret->event_task = sys_event_task_alloc(&cfg);
    assert(ret->event_task);

    return ret;
}

static inline errno_t
irqthread_start(struct _irqthread * irqthread)
{
    errno_t const err = sys_thread_start(irqthread->SYS);
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

    errno_t err = irqthread_start(irqthread);
    if (err != E_OK) {
	irqthread_destroy(irqthread);
	return ERR_PTR(err);
    }

    return irqthread;
}

/*** Timers ***/
extern void UMC_alarm_handler(void * const v_timer, uint64_t const now, errno_t);

struct timer_list {
    void	          (*function)(uintptr_t);   /* kernel-code handler */
    uintptr_t		    data;		    /* kernel-code handler arg */
    uint64_t		    expires;		    /* expiration "jiffy" time */
    sys_alarm_entry_t	    alarm;		    /* non-NULL when alarm pending (ticking) */
};

#define init_timer(timer)		memset(timer, 0, sizeof(*timer))
#define timer_pending(timer)		((timer)->alarm != NULL)
#define setup_timer(_timer, _fn, _data)	do { init_timer(_timer);		    \
					     (_timer)->function = (_fn);	    \
					     (_timer)->data = (uintptr_t)(_data);   \
					} while (0)

/* Callable from any thread (but only one) to cancel a timer */
static inline void
del_timer_sync(struct timer_list * timer)
{
    sys_alarm_entry_t alarm = timer->alarm;
    if (unlikely(alarm == NULL)) return;    /* not pending -- ignore */

    /* sys_alarm_cancel() cancels if possible; otherwise synchronizes with delivery to
     * guarantee the event task thread is not (any longer) executing the handler (for
     * the alarm we tried to cancel) at the time sys_alarm_cancel() returns to us here.
     */
    errno_t const err = sys_alarm_cancel(UMC_irqthread->event_task, alarm);

    /* The alarm now either has been cancelled, xor its delivery callback has completed
     * (in either case the alarm entry itself has been freed)
     */
    if (likely(err == E_OK)) {
	timer->alarm = NULL;		/* Cancelled the alarm */
    } else {
	assert_eq(err, EINVAL);		/* alarm entry not found on list */
	assert_eq(timer->alarm, NULL);	/* UMC_alarm_handler cleared this */
    }
}

#define add_timer(timer)		_add_timer((timer), FL_STR)
static inline void
_add_timer(struct timer_list * timer, sstring_t whence)
{
    assert_eq(timer->alarm, NULL);
    assert(timer->function);
    expect(timer->expires, "Adding timer with expiration at time zero");
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

/*** Work queues ***/

/* Has to be embedded in some other state, having no env pointer */
struct work_struct {
    struct list_head	    entry;
    void		  (*fn)(struct work_struct *);
    void	          * lockdep_map;    /* unused */
};

#define INIT_WORK(WORK, _fn)		do { INIT_LIST_HEAD(&(WORK)->entry); \
					     (WORK)->fn = (_fn); \
					} while (0)

struct delayed_work {
    struct work_struct	    work;   /* consumer expects this substructure */
    struct timer_list	    timer;
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
    struct wait_queue_head	    wake;
    bool		   volatile is_idle;
    atomic_t		   volatile is_flushing;
    struct wait_queue_head	    flushed;
    char			    name[64];
    struct task_struct            * owner;
};

extern errno_t UMC_work_queue_thr(void * v_workq);

static inline struct workqueue_struct *
create_workqueue(sstring_t name)
{
    struct workqueue_struct * workq = vzalloc(sizeof(*workq));
    INIT_LIST_HEAD(&workq->list);
    spin_lock_init(&workq->lock);
    init_waitqueue_head(&workq->wake);
    init_waitqueue_head(&workq->flushed);
    strncpy(workq->name, name, sizeof(workq->name)-1);

    spin_lock(&workq->lock);	/* synchronize with owner assertion in UMC_work_queue_thr */
    workq->owner = kthread_run(UMC_work_queue_thr, workq, "%s", name);
    spin_unlock(&workq->lock);

    return workq;
}

static inline void
destroy_workqueue(struct workqueue_struct * workq)
{
    kthread_stop(workq->owner);
    vfree(workq);
}

#define queue_work(WORKQ, WORK)	\
	    ( !list_empty(&(WORK)->entry) \
	        ? false	/* already on list */ \
	        : ({ bool do_wake = false; \
		     spin_lock(&(WORKQ)->lock); \
	             {   list_add_tail(&(WORKQ)->list, &(WORK)->entry); \
		         if (unlikely((WORKQ)->is_idle)) do_wake = true; \
	             } spin_unlock(&(WORKQ)->lock); \
		     if (unlikely(do_wake)) wake_up(&(WORKQ)->wake); \
		     true;	/* now on list */ }) \
	    )

#define flush_workqueue(WORKQ) \
	    do { spin_lock(&(WORKQ)->lock); \
		 {   atomic_inc(&(WORKQ)->is_flushing); \
		     wake_up(&(WORKQ)->wake); \
		     wait_event_locked((WORKQ)->flushed, \
			   list_empty(_VOLATIZE(&(WORKQ)->list)), lock, (WORKQ)->lock); \
		 } \
		 spin_unlock(&(WORKQ)->lock); \
	    } while (0);

/* Global general-use work queue */
extern struct workqueue_struct * UMC_workq;
#define schedule_work(WORK)		queue_work(UMC_workq, (WORK))
#define flush_scheduled_work()		flush_workqueue(UMC_workq)

//XXXX Limitation: nasty hack only works if WORK is on the general-use work queue
#define flush_work(WORK)		do { _USE(WORK); flush_scheduled_work(); } while (0)
#define cancel_work_sync(WORK)		do { _USE(WORK); flush_scheduled_work(); } while (0)

/***** Sockets and files *****/
/* Note:  for our limited usage we simply EMBED (sock) into (socket) into (inode) into (file) */

struct sock;	    /*   A/K/A  "sk"	    */
struct socket;	    /*   A/K/A  "sock"	    */

struct sk_prot {
    void                  (*disconnect)(struct sock *, int);
};

struct sock {
    uint16_t sk_family;
    union {
	struct {
	    struct in_addr daddr;   /* apparently this is supposed to be the PEER name */
	} inet_sk;
	struct {
	    /* XXX inet6 unsupported */
	} inet6_sk;
    };
    int			    sk_state;			    /* e.g. TCP_ESTABLISHED */
    rwlock_t		    sk_callback_lock;		    /* protect changes to callbacks */
    void		  * sk_user_data;			/* protocol connection */
    void		  (*sk_data_ready)(struct sock *, int); /* protocol callbacks */
    void		  (*sk_write_space)(struct sock *);
    void		  (*sk_state_change)(struct sock *);
    struct sk_prot	  * sk_prot;
    struct sk_prot	    sk_prot_s;
};

#define inet_sk(sk)			(&(sk)->inet_sk)
#define inet6_sk(sk)			(&(sk)->inet6_sk)

#define NIPQUAD(daddr)			(0xff&(((daddr).s_addr)    )), \
					(0xff&(((daddr).s_addr)>> 8)), \
					(0xff&(((daddr).s_addr)>>16)), \
					(0xff&(((daddr).s_addr)>>24))

struct socket_ops {
    void                  (*shutdown)(struct socket *, int);
    void                  (*setsockopt)(struct socket *, int, int, void *, int);
    ssize_t               (*sendpage)(struct socket *, struct page *, int, size_t, int);
};

#define RCV_SHUTDOWN			1
#define SEND_SHUTDOWN			2

struct socket {
    struct sock		  * sk;			/* points at embedded sk_s */
    struct sock		    sk_s;
    struct socket_ops     * ops;
    struct socket_ops       ops_s;
    int			    fd;			/* backing usermode fd number (sockets) */
    sys_event_task_t	    wr_poll_event_task;	/* thread of event thread for this fd */
    sys_poll_entry_t	    wr_poll_entry;	/* unique poll descriptor for this fd */
    sys_event_task_t	    rd_poll_event_task;
    sys_poll_entry_t	    rd_poll_entry;
    struct _irqthread     * rd_poll_event_thread;
};

typedef uint32_t umode_t;
#define S_IRUGO				(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO				(S_IWUSR|S_IWGRP|S_IWOTH)

struct proc_inode {
    struct proc_dir_entry * pde;
};

struct block_device {
    struct inode	  * bd_inode;
};

struct inode {
    umode_t		    i_mode;		/* e.g. S_ISREG */
    size_t		    i_size;		/* device or file size in bytes */
    struct block_device   * i_bdev;		/* unused */
    struct block_device     bdev_s;
    int			    i_type;
    union {
	struct socket	    sock_s;
	struct proc_inode   proc_s;
    };
    uint32_t		    openflags;
};

#define I_TYPE_FILE			1
#define I_TYPE_SOCK			2
#define I_TYPE_PROC			3

#define SOCKET_I(inode)			(&(inode)->sock_s)
#define PROC_I(inode)			(&(inode)->proc_s)
#define PDE(inode)			(PROC_I(inode)->pde)

struct file {
    void		  * private_data;	/* e.g. seq_file */
    void		  * f_mapping;		/* unused */
    struct inode	  * inode;		/* points at embedded inode_s */
    struct inode	    inode_s;
    int			    fd;			/* backing usermode fd */
};

#define file_inode(file)		((file)->inode)
#define i_size_read(inode)		((inode)->i_size)

/* The first argument is a real usermode fd */
static inline struct file *
_file_alloc(unsigned int fd, int i_type, umode_t mode, size_t size, uint32_t openflags)
{
    struct file * file = vzalloc(sizeof(*file));
    file->fd = fd;
    file->inode = &file->inode_s;
    file->inode->i_mode = mode;
    file->inode->i_size = size;
    file->inode->i_type = i_type;
    file->inode->openflags = openflags;
    file->inode->i_bdev = &file->inode->bdev_s;
    file->inode->i_bdev->bd_inode = file->inode;
    return file;
}

#define _fput(file)			vfree(file)

/***** Sockets *****/

#define kernel_sendmsg(sock, msg, vec, nvec, nbytes) \
	    ({  (msg)->msg_iov = (vec); \
		(msg)->msg_iovlen = (nvec); \
		/* These reflect current expected usage, not limitations */ \
		expect_eq((nvec), 1, "maybe remove this warning"); \
		expect_eq((nbytes), (vec)->iov_len, "maybe remove this warning"); \
		UMC_kernelize(sendmsg((sock)->fd, (msg), (msg)->msg_flags)); \
	    })

static inline int
sock_recvmsg(struct socket * sock, struct msghdr * msg, size_t nbytes, int flags) \
{
    ssize_t rc = UMC_kernelize(recvmsg((sock)->fd, (msg), (flags)));
    if (rc > 0) {
	size_t skipbytes = rc;
	while (skipbytes && skipbytes >= (msg)->msg_iov->iov_len) {
	    (msg)->msg_iov->iov_base += skipbytes;	/*XXX needed? */
	    skipbytes -= (msg)->msg_iov->iov_len;
	    (msg)->msg_iov->iov_len = 0;
	    ++(msg)->msg_iov;
	    assert((msg)->msg_iovlen);
	    --(msg)->msg_iovlen;
	}
	(msg)->msg_iov->iov_base += skipbytes;
	(msg)->msg_iov->iov_len -= skipbytes;
    } else if (rc == 0) {
	trace("EOF on fd=%d", (sock)->fd);
    } else {
	 if (rc != -EAGAIN) {
	     sys_warning("ERROR %"PRId64" '%s'on fd=%d", rc, strerror(-rc), (sock)->fd);
	     sys_breakpoint();
	 }
    }
    return rc;
}

/* The sock->ops point to these shim functions */
extern ssize_t sock_no_sendpage(struct socket *sock,
				struct page *page, int offset, size_t size, int flags);
extern void UMC_sock_shutdown(struct socket *, int k_how);
extern void UMC_sock_discon(struct sock *, int XXX);
extern void UMC_sock_setsockopt(struct socket *,
				int level, int optname, void *optval, int optlen);

/* These are the original targets of the sk callbacks before the app intercepts them */
extern void UMC_sock_cb_read(struct sock *, int obsolete);
extern void UMC_sock_cb_write(struct sock *);
extern void UMC_sock_cb_state(struct sock *);
extern void UMC_sock_recv_event(void * env, uintptr_t events, errno_t err);
extern void UMC_sock_xmit_event(void * env, uintptr_t events, errno_t err);

/* Wrap a backing usermode SOCKET fd inside a simulated kernel struct file * */
//XXX Support for fget/fput presently limited to sockets, one reference only
static inline struct file *
fget(unsigned int daemon_fd)
{
    int fd = dup(daemon_fd);	/* caller still owns the original */
    trace("fget dups %d to %d", daemon_fd, fd);

    struct file * file = _file_alloc(fd, I_TYPE_SOCK, 0, 0, 0);

    struct socket * sock = SOCKET_I(file->inode);
    sock->fd = fd;

    /* Set pointers to internal embedded structures */
    sock->ops = &sock->ops_s;
    sock->sk = &sock->sk_s;
    sock->sk->sk_prot = &sock->sk->sk_prot_s;

    /* Socket operations callable by application */
    sock->ops->shutdown = UMC_sock_shutdown;
    sock->ops->setsockopt = UMC_sock_setsockopt;
    sock->ops->sendpage = sock_no_sendpage;
    sock->sk->sk_prot->disconnect = UMC_sock_discon;

    /* State change callbacks to the application, delivered by event_task */
    sock->sk->sk_state_change = UMC_sock_cb_state;
    sock->sk->sk_data_ready = UMC_sock_cb_read;
    sock->sk->sk_write_space = UMC_sock_cb_write;

    rwlock_init(&sock->sk->sk_callback_lock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t addrlen = sizeof(addr);
    int rc = getpeername(fd, &addr, &addrlen);
    if (likely(rc == 0)) {
	sock->sk->sk_family = addr.sin_family;
	inet_sk(sock->sk)->daddr = addr.sin_addr;
    }

    //XXXX TUNE how sockets relate to event threads
    /* For now using one "softirq" thread for transmit-ready notifications shared by
     * ALL sockets, and one softirq thread for receive processing for EACH socket.
     */
    sock->wr_poll_event_task = UMC_irqthread->event_task;
    sock->wr_poll_entry = sys_poll_enable(sock->wr_poll_event_task,
					  UMC_sock_xmit_event,
					  SOCKET_I(file->inode), fd,
					  SYS_SOCKET_XMIT_ET, "socket_xmit_poll_entry");

    sock->rd_poll_event_thread = irqthread_run("%d.%d.%d.%d", NIPQUAD(addr.sin_addr));
    sock->rd_poll_event_task = sock->rd_poll_event_thread->event_task;
    sock->rd_poll_entry = sys_poll_enable(sock->rd_poll_event_task,
					  UMC_sock_recv_event,
				          SOCKET_I(file->inode), fd,
				          SYS_SOCKET_RECV_ET, "socket_recv_poll_entry");

    sock->sk->sk_state = TCP_ESTABLISHED;
    return file;
}

#define fput(sockfile) \
	    do { assert_eq(sockfile->inode->i_type, I_TYPE_SOCK); \
		 sys_poll_disable(SOCKET_I((sockfile)->inode)->wr_poll_event_task, \
				  SOCKET_I((sockfile)->inode)->wr_poll_entry); \
		 sys_poll_disable(SOCKET_I((sockfile)->inode)->rd_poll_event_task, \
				  SOCKET_I((sockfile)->inode)->rd_poll_entry); \
		 irqthread_stop(SOCKET_I((sockfile)->inode)->rd_poll_event_thread); \
		 irqthread_destroy(SOCKET_I((sockfile)->inode)->rd_poll_event_thread); \
		 close((sockfile)->fd); \
		 _fput(sockfile); \
	    } while (0)

/***** Files on disk, or block devices *****/

static inline struct file *
filp_open(const char * name, int flags, umode_t mode)
{
    int fd = open(name, flags, mode);
    if (unlikely(fd < 0)) {
	return ERR_PTR(-errno);
    }

    assert((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR);

    struct stat statbuf;
    errno_t const err = UMC_kernelize(fstat(fd, &statbuf));
    if (unlikely(err != E_OK)) {
	close(fd);
	return ERR_PTR(err);
    }

    /* This appears to be the way to get the size of a block device or a file */
    off_t lseek_end_ofs = lseek(fd, 0, SEEK_END); /* (go back) */ lseek(fd, 0, SEEK_SET);

    assert_imply(S_ISREG(statbuf.st_mode), statbuf.st_size == lseek_end_ofs);

#ifdef USERMODE_AIO
#define S_BLOCKIO_TYPE	S_IFBLK	    /* make block devices look like block devices */
#else
#define S_BLOCKIO_TYPE	S_IFREG	    /* make block devices look like files */
#endif

    /* Hack /dev/zero to look like a big block device (or file) */
    if (S_ISCHR(statbuf.st_mode)) {
        struct stat zero_statbuf;
        int rc = stat("/dev/zero", &zero_statbuf);
        if (rc == 0 && statbuf.st_rdev == zero_statbuf.st_rdev) {
	    statbuf.st_size = 1ull << 40;
	    statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
        }
    } else if (S_ISBLK(statbuf.st_mode)) {
	statbuf.st_size = lseek_end_ofs;
	statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
    }

    sys_notice("name='%s' fd=%d statbuf.st_size=%"PRIu64" lseek_end_ofs=%"PRId64"/0x%"PRIx64,
	       name, fd, statbuf.st_size, lseek_end_ofs, lseek_end_ofs);

    return _file_alloc(fd, I_TYPE_FILE, statbuf.st_mode, statbuf.st_size, flags);
}

static inline void
filp_close(struct file * file, void * unused)
{
    assert_eq(file->inode->i_type, I_TYPE_FILE);
    close(file->fd);
    _fput(file);
}

#define vfs_read(file, addr, nbytes, seekposp) \
	    ({ \
		int _rc = UMC_kernelize(pread((file)->fd, (addr), (nbytes), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_write(file, addr, nbytes, seekposp) \
	    ({ \
		int _rc = UMC_kernelize(pwrite((file)->fd, (addr), (nbytes), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_readv(file, addr, nbytes, seekposp) \
	    ({ \
		int _rc = UMC_kernelize(preadv((file)->fd, (addr), (nbytes), *(seekposp))); \
		if (likely(_rc > 0)) *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_writev(file, addr, nbytes, seekposp) \
	    ({ \
		int _rc = -1; \
		if ((file)->inode->i_type == I_TYPE_SOCK) { \
		    _rc = UMC_kernelize(writev((file)->fd, (addr), (nbytes))); \
		} else { \
		    verify_eq((file)->inode->i_type, I_TYPE_FILE); \
		    _rc = UMC_kernelize(pwritev((file)->fd, (addr), (nbytes), *(seekposp))); \
		    if (likely(_rc > 0)) *(seekposp) += _rc; \
		} \
		_rc; \
	    })

/* Note anachronism:  this simulates the vfs_fsync definition from LINUX_VERSION 2.6.35 */
#define vfs_fsync(file, datasync) ((datasync) ? fdatasync((file)->fd) : fsync((file)->fd))

static inline errno_t
sync_page_range(struct inode * inode, void * mapping, loff_t offset, loff_t nbytes)
{
    struct file * file = container_of(inode, struct file, inode_s);  /* embedded */
    assert(file->fd);

    errno_t err =  UMC_kernelize(sync_file_range(file->fd, offset, nbytes,
	    SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER));

    if (err == -ESPIPE) err = E_OK;	//XXX /dev/zero
    return err;
}

/* seq ops have to do with /proc */

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

#define seq_lseek			NULL	/* unused */

struct seq_file {
    struct seq_operations const   * op;		/* start, show, next, stop */
    void			  * private;	/* show sub-function */
    string_t			    reply;	/* accumulates seq_printfs */
};

struct seq_operations {
    void		      * (*start)(struct seq_file *, loff_t * pos);
    void		      * (*next)(struct seq_file *, void *, loff_t * pos);
    void		        (*stop)(struct seq_file *, void *);
    int 		        (*show)(struct seq_file *, void *);
};

#define seq_printf(seq, fmtargs...) ((seq)->reply = string_concat_free((seq)->reply, sys_sprintf(""fmtargs)))

/* string_concat_free() appends suffix string to prefix string, CONSUMING BOTH and returning
 * the concatination -- either or both strings may be NULL -- if both, NULL is returned.
 */
//XXXXXX API? string_concat_free
#define string_concat_free(prefix, suffix) mem_string_concat_free((prefix), (suffix), FL_STR)
string_t mem_string_concat_free(string_t const prefix, string_t const suffix,
							sstring_t const caller_id);

static inline errno_t
seq_open(struct file * const file, struct seq_operations const * const ops)
{
    struct seq_file * seq = vzalloc(sizeof(*seq));
    assert_eq(file->private_data, NULL);
    file->private_data = seq;
    seq->op = ops;
    return E_OK;
}

static inline errno_t
seq_release(struct inode * const unused, struct file * const file)
{
    struct seq_file * seq_file = file->private_data;
    file->private_data = NULL;
    kfree(seq_file);
    return E_OK;
}

static inline errno_t
single_open(struct file * const file, int (*show)(struct seq_file *, void *), void * data)
{
    struct seq_operations *op = vzalloc(sizeof(*op));
    op->start = NULL;
    op->next = NULL;
    op->stop = NULL;
    op->show = show;
    errno_t err = seq_open(file, op);
    if (err == E_OK) {
	((struct seq_file *)file->private_data)->private = data;
    }
    return err;
}

static inline errno_t
single_release(struct inode * const inode, struct file * const file)
{
    const struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
    int rc = seq_release(inode, file);
    vfree(op);
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
    return NULL;
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
seq_fmt(struct seq_file * const seq)
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
        errno_t rc = seq->op->show(seq, list_item);
        assert_eq(rc, E_OK);
        list_item = seq->op->next(seq, list_item, &pos);
    }

    seq->op->stop(seq, list_item);
}

static inline ssize_t
seq_read(struct file * const file, void * buf, size_t size, loff_t * lofsp)
{
    struct seq_file * seq = file->private_data;

    seq_fmt(seq);

    uint32_t reply_len = seq->reply ? strlen(seq->reply) : 0;

    if (*lofsp >= reply_len) {
	reply_len = 0;
    } else {
	reply_len -= *lofsp;
    }

    if (reply_len > size) reply_len = size;

    if (reply_len) {
	memcpy(buf, seq->reply + *lofsp, reply_len);
	*lofsp += reply_len;
    }

    if (seq->reply) vfree(seq->reply);

    return reply_len;
}

/* /proc is simulated by mapping our proc_dir_entry tree to the FUSE filesystem interface */

/* Internal representation of (simulated) /proc tree */
struct proc_dir_entry {
    struct proc_dir_entry	      * parent;	    /* root's parent is NULL */
    struct proc_dir_entry	      * sibling;    /* null terminated list */
    struct proc_dir_entry	      * child;	    /* first child (if nonempty DIR) */
    struct module		      * owner;	    /* still in 2.6.24 */
    const struct file_operations      *	proc_fops;
    void			      * data;
    umode_t				mode;
    time_t				atime;
    time_t				mtime;
    u8					namelen;
    char				name[1];    /* space for '\0' */
};

/* Application calls here to create/update PDE tree -- a NULL parent refers to the root node */
extern struct proc_dir_entry * pde_create(char const *, umode_t, struct proc_dir_entry *,
					        const struct file_operations *, void *);

#define proc_create_data(name, mode, parent, fops, data) \
	    pde_create((name), (mode), (parent), (fops), (data))

#define proc_create(name, mode, parent, fops) \
		proc_create_data((name), (mode), (parent), (fops), NULL)

#define create_proc_entry(name, mode, parent) \
		proc_create_data((name), (mode), (parent), NULL, NULL)

#define proc_mkdir(name, parent)	      \
		proc_create_data((name), PROC_DIR_UMODE, (parent), NULL, NULL)

#define PROC_ROOT_UMODE			(S_IFDIR | 0555)
#define PROC_DIR_UMODE			(S_IFDIR | 0555)
#define PROC_FILE_UMODE_R		(S_IFREG | 0444)
#define PROC_FILE_UMODE_RW		(S_IFREG | 0664)

extern struct proc_dir_entry * pde_remove(char const * name, struct proc_dir_entry * parent);

#define remove_proc_entry(name, parent) \
	    do { struct proc_dir_entry * pde = pde_remove(name, (parent)); \
		 if (pde) vfree(pde); \
	    } while (0)

/* This hack is for accessing "module_param_named" variables */
//XXX You can write them, but unless someone then notices the changed value, nothing happens

struct proc_dir_entry * pde_module_param_create(char const *, void *, size_t, umode_t);
struct proc_dir_entry * pde_module_param_remove(char const * name);

/* Each instance in the source of module_param_named() here defines two functions to add and
 * remove a reference to the named variable in the PDE tree.  The functions are called from
 * the application compatibility init and exit functions (e.g. SCST_init)
 */
#define module_param_named(procname, varname, vartype, modeperms) \
 extern void CONCAT(SCST_param_create_, procname)(void); \
        void CONCAT(SCST_param_create_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    pde_module_param_create(#procname, &varname, sizeof(varname), (modeperms)); \
	} \
 \
 extern void CONCAT(SCST_param_remove_, procname)(void); \
        void CONCAT(SCST_param_remove_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    struct proc_dir_entry * pde = pde_module_param_remove(#procname); \
	    if (pde) vfree(pde); \
	}

#define module_param(var, type, mode)	module_param_named(var, var, type, (mode))

/* Start/control the FUSE thread */
extern errno_t pde_fuse_start(char * mountpoint);
extern errno_t pde_fuse_stop(void);
extern errno_t pde_fuse_exit(void);

////////////////////////////////////////////////////////////////////////////////

/***** Stub out some definitions unused in usermode builds *****/

#define MODULE_VERSION(str) static __unused \
		string_t MODULE_VERSION = ("MODULE_VERSION='"str"_LIB'" \
					       "(adapted to usermode)")

#define MODULE_LICENSE(str) static __unused \
		string_t MODULE_LICENSE = ("MODULE_LICENSE='"str"'")

#define MODULE_AUTHOR(str) static __unused \
		string_t MODULE_AUTHOR = ("MODULE_AUTHOR='"str"'" \
					      "\nUsermode adaptations by DAB")

#define MODULE_DESCRIPTION(str) static __unused \
		string_t MODULE_DESCRIPTION = ("MODULE_DESCRIPTION='"str"'")

#define MODULE_NAME_LEN			56
struct modversion_info { unsigned long crc; char name[MODULE_NAME_LEN]; };
struct module { char name[MODULE_NAME_LEN]; int arch; };

#define MODULE_INFO(ver, str)		/* */
#define MODULE_PARM_DESC(var, desc)	/* */
#define get_module_info(arg)		(-EINVAL)
#define MODULE_ARCH_INIT		0xED0CBAD0
#define try_module_get(module)		true
#define module_put(module)		DO_NOTHING()

#define EXPORT_SYMBOL(sym)		/* */
#define EXPORT_SYMBOL_GPL(sym)		/* */

#define	__GFP_NOFAIL			1 /* no effect but sometimes checked */

#define	__GFP_HIGHMEM			IGNORED
#define	__GFP_NOWARN			IGNORED
#define	__GFP_ZERO			IGNORED
#define	GFP_ATOMIC			IGNORED
#define	GFP_DMA				IGNORED
#define	GFP_KERNEL			IGNORED
#define GFP_NOIO			IGNORED
#define DEFAULT_SEEKS			IGNORED
#define KERNEL_DS			IGNORED
#define KM_SOFTIRQ0			IGNORED
#define KM_SOFTIRQ1			IGNORED
#define KM_USER0			IGNORED
#define KM_USER1			IGNORED
#define PF_NOFREEZE			IGNORED
#define TASK_INTERRUPTIBLE		IGNORED

#define get_fs()			IGNORED
#define get_ds()			IGNORED
#define set_fs(newfs)			DO_NOTHING( _USE(newfs) )

struct mm_struct { void * mmap_sem; };
typedef void * mm_segment_t;
enum km_type { FROB };
struct vm_area_struct;

#define get_user_pages(a,b,c,d,e,f,g,h)	({ FATAL(get_user_pages); IGNORED; })

struct shrinker {
    void * count_objects;
    void * scan_objects;
    int seeks;
    int (*shrink)(int, gfp_t);
};
struct shrink_control { int nr_to_scan; };
#define register_shrinker(shrinker)	DO_NOTHING( _USE(shrinker) )
#define unregister_shrinker(shrinker)	DO_NOTHING()

#define STATIC_LOCKDEP_MAP_INIT(name, key)  NULL

/* "local" functions shouldn't need to do anything beyond what associated lock accomplishes */
#define local_bh_disable()		DO_NOTHING()
#define local_bh_enable()		DO_NOTHING()
#define irqs_disabled()			false
#define local_irq_save(saver)		DO_NOTHING( _USE(saver) )
#define local_irq_restore(saver)	DO_NOTHING()
#define local_irq_disable()		DO_NOTHING()
#define local_irq_enable()		DO_NOTHING()

struct attribute {
    const char	      * name;
    umode_t             mode;
    void	      * owner;
};

struct kobject {
    struct kref		kref;
    char	      * name;
    struct kobj_type  * ktype;
    struct kobject    * parent;
};

struct kobj_attribute {
    struct attribute attr;
    ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
};

#define __ATTR(_name, _mode, _show, _store) {			    \
    .attr = { .name = __stringify(_name), .mode = _mode },	    \
    .show   = _show,                                                \
    .store  = _store,                                               \
}

struct kobj_type {
    void * default_attrs;
    void * release;
    struct sysfs_ops const * sysfs_ops;
    ssize_t (*show)(struct kobject *kobj, struct attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
};

#define kobject_init(kobj)		DO_NOTHING()
#define kobject_put(kobj)		DO_NOTHING()

struct class_device;
struct class_interface {
    int (*add)(struct class_device *cdev, struct class_interface *intf);
    void (*remove)(struct class_device *cdev, struct class_interface *intf);
};

#define kfree_rcu()			FATAL(kfree_rcu)

#define register_chrdev(major, name, fops)	(_USE(name), E_OK)
#define unregister_chrdev(major, name)		DO_NOTHING()
#define scsi_register_interface(interface)	(_USE(interface), E_OK)
#define scsi_unregister_interface(interface)	DO_NOTHING()

struct nameidata;
struct dentry;

#define bdev_get_queue(x)		NULL

enum dma_data_direction { DMA_NONE, DMA_FROM_DEVICE, DMA_TO_DEVICE, DMA_BIDIRECTIONAL };
typedef struct { } dma_addr_t;
typedef int sector_t;
#define put_io_context(c)		DO_NOTHING()

struct tasklet_struct { };

#define tasklet_init(x, y, z)		DO_NOTHING()
#define tasklet_schedule(tasklet)	FATAL(tasklet_schedule)

#define preempt_disable()		DO_NOTHING()
#define preempt_enable()		DO_NOTHING()

extern uint64_t crc32c_uniq;	//XXX hack makes these unique -- no good for matching
#define crc32c(x, y, z)			(++crc32c_uniq)

/////////////////////////////////

struct bio;
typedef void (bio_end_io_t) (struct bio *, int);

struct request_queue {
    void (*unplug_fn)(void *);
};

struct bio_vec {
        struct page     *bv_page;
        unsigned int    bv_len;
        unsigned int    bv_offset;
};

struct bio {
	sector_t		bi_sector;	/* device address in 512 byte sectors */
	struct bio		*bi_next;	/* request queue link */
	struct block_device	*bi_bdev;
	unsigned long		bi_flags;	/* status, command, etc */
	unsigned long		bi_rw;		/* bottom bits READ/WRITE, top bits priority */
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	unsigned short		bi_idx;		/* current index into bvl_vec */
	unsigned int		bi_phys_segments; /* Number of segments in this BIO after physical address coalescing is performed.  */
	unsigned int		bi_size;	/* residual I/O count */
	/* To keep track of the max segment size, we account for the sizes of the first and last mergeable segments in this bio.  */
	unsigned int		bi_seg_front_size;
	unsigned int		bi_seg_back_size;
	bio_end_io_t		*bi_end_io;
	void			*bi_private;
	struct bio_integrity_payload *bi_integrity;  /* data integrity */

	unsigned int		bi_max_vecs;	/* max bvl_vecs we can hold */
	atomic_t		bi_cnt;		/* pin count */
	struct bio_vec		*bi_io_vec;	/* the actual vec list */
	struct bio_set		*bi_pool;
	struct bio_vec		bi_inline_vecs[0];
};

#define BIO_MAX_PAGES			1024
#define BIO_RW				IGNORED
#define BIO_RW_FAILFAST			IGNORED
#define BIO_RW_META			IGNORED
#define BIO_RW_SYNC			IGNORED
#define BIO_UPTODATE			IGNORED
#define READ_SYNC			IGNORED
#define REQ_FUA				IGNORED

#define bio_get_nr_vecs(bdev)		BIO_MAX_PAGES

#define is_vmalloc_addr(addr)		false
#define vmalloc_to_page(addr)		virt_to_page(addr)		
#define offset_in_page(addr)		virt_to_page_ofs(addr)			

#define bio_flagged(bio, flag)		true //XXX BIO_UPTODATE

#define bio_add_page(bio, pg, bytes, off)	    (_USE(pg), 0)
#define bio_alloc(gfp, max_vec)			    (_USE(max_vec), NULL)
#define bio_put(bio)				    FATAL(bio_put)
#define submit_bio(op, bio)			    FATAL(submit_bio)

#endif	/* USERMODE_LIB_H */
