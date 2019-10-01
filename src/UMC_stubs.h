/* UMC_stubs.h -- Usermode compatibility: stubs for unimplemented functions
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_STUBS_H
#define UMC_STUBS_H

// #include <linux/crc32c.h>		// lib/libcrc32c.c
extern uint32_t crc32c_uniq;		//XXX hack makes these unique -- no good for matching
#define crc32c(x, y, z)			(++crc32c_uniq)	//XXX

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
#define crypto_alloc_hash(type_str, x, alg)		NULL		//XXX
#define crypto_hash_init(hash)				0		//XXX
#define crypto_hash_update(hash, sg, nbytes)		0		//XXX
#define crypto_hash_final(hash, id)			0		//XXX
#define crypto_free_hash(tfm)				DO_NOTHING()	//XXX

#define crypto_ahash_digestsize(h)			UMC_STUB(crypto_ahash_digestsize)
#define crypto_ahash_final(h)				UMC_STUB(crypto_ahash_final)
#define crypto_ahash_init(h)				UMC_STUB(crypto_ahash_init)
#define crypto_ahash_reqsize(h)				UMC_STUB(crypto_ahash_reqsize)
#define crypto_ahash_reqtfm(h)				UMC_STUB(crypto_ahash_reqtfm)
#define crypto_ahash_update(h)				UMC_STUB(crypto_ahash_update)
#define crypto_alloc_ahash(a, b, c)			NULL		//XXX
#define crypto_free_ahash(h)				DO_NOTHING()

#define crypto_shash_digestsize(tfm)			UMC_STUB(crypto_shash_digestsize)
#define crypto_shash_final(d, out)			UMC_STUB(crypto_shash_final)
#define crypto_shash_init(d)				UMC_STUB(crypto_shash_init)
#define crypto_shash_descsize(d)			UMC_STUB(crypto_shash_descsize)
#define crypto_shash_update(d, addr, len)		UMC_STUB(crypto_shash_update)
#define crypto_alloc_shash(a, b, c)			NULL		//XXX
#define crypto_free_shash(h)				DO_NOTHING()

#define generic_unplug_device(q)	DO_NOTHING()

struct class_device;
struct class_interface {
    int (*add)(struct class_device *cdev, struct class_interface *intf);	/* <  2.6.26 */
    void (*remove)(struct class_device *cdev, struct class_interface *intf);	/* <  2.6.26 */
    int (*add_dev)(struct device *cdev, struct class_interface *intf);		/* >= 2.6.26 */
    void (*remove_dev)(struct device *cdev, struct class_interface *intf);	/* >= 2.6.26 */
};

#define register_chrdev(major, name, fops)	(_USE(name), 0)
#define unregister_chrdev(major, name)		DO_NOTHING()

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
    return NULL;
}

#define ib_alloc_pd(device, flags...)	NULL

struct ib_cq_init_attr;

#define PF_NOFREEZE			IGNORED
#define DEFAULT_SEEKS			IGNORED

#define KERNEL_DS			IGNORED
#define get_ds()			IGNORED
#define get_fs()			IGNORED
#define set_fs(x)			DO_NOTHING(_USE(x))

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

#endif /* UMC_STUBS_H */
