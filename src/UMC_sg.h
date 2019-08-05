/* UMC_sg.h -- usermode compatibility for scatter/gather
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_SG_H
#define UMC_SG_H
#include "UMC_sys.h"

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

    return 0;
}

static inline int
sg_free_table(struct sg_table *table)
{
    kfree(table->sgl);
    table->sgl = NULL;
    return 0;
}

#endif /* UMC_SG_H */
