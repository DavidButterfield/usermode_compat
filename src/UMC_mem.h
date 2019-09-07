/* UMC_mem.h -- Usermode compatibility: memory allocation
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_MEM_H
#define UMC_MEM_H
#include "UMC_sys.h"

#define vmalloc(size)			sys_mem_alloc(size)
#define vzalloc(size)			sys_mem_zalloc(size)
#define vrealloc(oaddr, nsize)		sys_mem_realloc((oaddr), (nsize))
#define vfree(addr)			do { if (likely(addr)) sys_mem_free(addr); } while (0)

#define kalloc(size, gfp)		(((gfp) & __GFP_ZERO) ? vzalloc(size) : vmalloc(size))
#define kzalloc(size, gfp)		(_USE(gfp), vzalloc(size))
#define kzalloc_node(size, gfp, nodeid) (_USE(nodeid), kzalloc((size), (gfp)))

#define krealloc(oaddr, nsize, gfp)	(_USE(gfp), vrealloc((oaddr), (nsize)))

#define kfree(addr)			vfree(addr)

#define kmalloc(size, gfp)		kalloc((size), (gfp))
#define kmalloc_track_caller(size, gfp)	kalloc((size), (gfp))
#define kcalloc(count, size, gfp)	kzalloc((count) * (size), (gfp))

#define __vmalloc(size, gfp, prot)	(_USE(prot), kalloc((size), (gfp)))

#define record_alloc_uninit(ptr_var)	((typeof(ptr_var))vmalloc(sizeof(*(ptr_var))))
#define record_alloc(ptr_var)		((typeof(ptr_var))vzalloc(sizeof(*(ptr_var))))
#define record_free(ptr_var)		vfree(ptr_var)
#define record_zero(ptr_var)		memset((ptr_var), 0, sizeof(*(ptr_var)))

#ifndef PAGE_SHIFT
#define PAGE_SHIFT			12U	/* need not match real kernel */
#endif

#define PAGE_SIZE			(1U << PAGE_SHIFT)
#define PAGE_MASK			(~((unsigned long)PAGE_SIZE - 1))

#define PAGE_ALIGN(size)		ALIGN((size), PAGE_SIZE)

#ifndef PAGE_CACHE_SHIFT
/* In theory this can be different from PAGE_SHIFT, but I'm not sure all the code is correct */
#define PAGE_CACHE_SHIFT		PAGE_SHIFT
#endif

#define PAGE_CACHE_SIZE			(1UL<<PAGE_CACHE_SHIFT)
#define PAGE_CACHE_MASK			(~(PAGE_CACHE_SIZE-1))

/* These "page" functions actually work on addresses, not struct page */
#define __get_free_page(gfp)		kalloc(PAGE_SIZE, (gfp))
#define __get_free_pages(gfp, order)	kalloc(PAGE_SIZE << (order), (gfp))
#define get_zeroed_page(gfp)		kzalloc(PAGE_SIZE, (gfp))
#define copy_page(dst, src)		memcpy((dst), (src), PAGE_SIZE)
#define nth_page(page, n)		((void *)(page) + (n)*PAGE_SIZE)
#define pages_free(addr, order)		kfree(addr)

#define free_page(addr)			free_pages((addr), 0)
#define free_pages(addr, order)		kfree((void *)addr)

#define is_vmalloc_addr(addr)		false	/* no special-case memory */
#define object_is_on_stack(addr)	false

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
#define kmem_cache_free(cache, ptr)	(_USE(cache), sys_buf_free((sys_buf_t)(ptr)))

#define kmem_cache_size(cache)		sys_buf_cache_size(cache)

static inline void
kmem_cache_destroy(struct kmem_cache * cache)
{
    error_t err = sys_buf_cache_destroy(cache);
    if (err == 0)
	return;
    pr_warning("kmem_cache not empty\n");
}

//XXX Limitation: kmem_cache doesn't currently support flags or constructor
static inline struct kmem_cache *
kmem_cache_create(const char * name, size_t size, size_t req_align,
		   unsigned int flags, void * constructor)
{
    size_t min_align;
    assert_eq(constructor, NULL);   /* XXX kmem_cache constructor unimplemented */
    assert_eq(flags & __GFP_ZERO, 0);	//XXX not implemented

    if (flags & SLAB_HWCACHE_ALIGN)
	min_align = __CACHE_LINE_BYTES;
    else min_align = sizeof(uint64_t);

    if (min_align < req_align)
	min_align = req_align;

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
    assert(alloc_fn);
    assert(free_fn);
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
    sys_buf_allocator_set(mp, caller_id);
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
#define kstrdup(string, gfp)		kmemdup(string, 1+strlen(string), (gfp))
#define vstrdup(string)			kstrdup(string, IGNORED)

/* Apparently this returns the (untruncated) length of the source */
#define strlcpy(dst, src, size)		(dst[(size)-1] = '\0',		    \
					 strncpy((dst), (src), (size)-1),   \
					 UMC_size_t_JUNK=strlen(src))

#define access_ok(type, addr, size)	true
#define copy_from_user(dst, src, len)	(memcpy((dst), (src), (len)), 0)
#define copy_to_user(dst, src, len)	(memcpy((dst), (src), (len)), 0)
#define get_user(id, ptr)		(((id) = *(ptr)), 0)
#define __get_user(id, ptr)		(((id) = *(ptr)), 0)
#define put_user(val, ptr)		((*(ptr) = (val)), 0)

#define get_user_pages(a,b,c,d,e,f,g,h)	0   /* pages always mapped in usermode */

#endif /* UMC_MEM_H */
