/* UMC_page.h -- usermode compatibility for struct page
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_PAGE_H
#define UMC_PAGE_H
#include "UMC_sys.h"
#include "UMC_lock.h"

struct page {
    struct list_head			UMC_page_list;
    struct list_head			lru;	/* field overloaded by drbd! */
    struct kref				kref;
    struct mutex			lock;
    unsigned short			order;	    /* log2(npages) */
    long				private;
    struct address_space	      * mapping;    /* keep NULL */
    void			      * vaddr;	    /* address of the buffer */
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

#define virt_to_page_addr(addr)		((struct page *)((uintptr_t)(addr) & PAGE_MASK))
#define virt_to_page_ofs(addr)		((size_t)((uintptr_t)(addr) & ~PAGE_MASK))

/* Ugh.  Search down the page list to find the one containing the specified addr */
//XXXX PERF virt_to_page needs a faster lookup
static inline struct page *
virt_to_page(const void * addr_v)
{
    const char * addr = addr_v;
    struct page * ret = NULL;
    struct page * page;
    spin_lock(&UMC_pagelist_lock);
    list_for_each_entry(page, &UMC_pagelist, UMC_page_list) {
	char * page_addr = page_address(page);
	if (page_addr <= addr && addr < page_addr + (1 << page->order)) {
	    ret = page;
	    break;
	}
    }
    spin_unlock(&UMC_pagelist_lock);
    expect_ne(ret, NULL, "could not find address %p in page list", addr);
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
//    But for now it looks like we only get called with order zero; that'll work.
#define alloc_pages(gfp, order)		_alloc_pages((gfp), (order), FL_STR)
static inline struct page *
_alloc_pages(gfp_t gfp, unsigned int order, sstring_t caller_id)
{
    //XXXX Use a kmem_cache for the page structure
    struct page * page = record_alloc(page);
    // mem_buf_allocator_set(page, caller_id);

    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = (unsigned short)order;

    expect_eq(order, 0, "usermode_lib.h: Check semantics for alloc_pages()");
    page_address(page) = __get_free_pages(gfp, order);
    // mem_buf_allocator_set(page_address(page), caller_id);

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
#define lock_page_killable(page)	({ mutex_lock(&(page)->lock); 0; })
#define trylock_page(page)		mutex_trylock(&(page)->lock)
#define unlock_page(page)		mutex_unlock(&(page)->lock)

#define ClearPageError(page)		DO_NOTHING()
#define PageReadahead(page)		0
#define PageSlab(page)			false
#define PageUptodate(page)		true

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

extern uint8_t __aligned(PAGE_SIZE) empty_zero_page[PAGE_SIZE];
extern struct page zero_page;
#define ZERO_PAGE(vaddr)		(expect_eq((vaddr), 0), &zero_page)

/* page_pool uses a pair of pools for the struct pages and the data pages */

static inline void *
_page_pool_alloc(gfp_t gfp, void * mp_v)
{
    mempool_t * mp = mp_v;
    struct page * page = kmem_cache_zalloc(mp->pool_data3, gfp);
    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = (unsigned short)mp->private;
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
    expect_eq(order, 0);	/* only order zero for now */
    mp->private = order;
    mp->destroy_fn = _page_pool_destroy;
    // mem_buf_allocator_set(mp, caller_id);
    return mp;
}

#endif /* UMC_PAGE_H */
