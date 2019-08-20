/* UMC_bio.h -- Usermode compatibility: block I/O
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_BIO_H
#define UMC_BIO_H
#include "UMC_sys.h"
#include "UMC_thread.h"
#include "UMC_inode.h"
#include "UMC_page.h"

#define trace_err(args...)		nlprintk(args)

extern const char * UMC_fuse_mount_point;   /* e.g. "/UMCfuse" *///XXXXXX

/*** Request Queue (mostly unused) ***/

typedef int				(congested_fn)(void *, int);

struct backing_dev_info {
    struct device		      * dev;
    char			      * name;
    unsigned long			ra_pages;	    /* keep zero */
    void			      * congested_data;	    /* unused */
    congested_fn		      * congested_fn;	    /* unused */
};

static inline int
bdi_congested(struct backing_dev_info * bdi_ptr, long bits)
{
    return 0;		//XXXX bdi_congested() always says "no"
}

#define bdi_read_congested(bdi)		bdi_congested(*(bdi), 1 << BDI_sync_congested)
#define BDI_async_congested		0
#define BDI_sync_congested		1

//XXX queue_limits ignored
struct queue_limits {
    unsigned int			discard_granularity;
    unsigned int			discard_alignment;
    unsigned int			max_discard_sectors;
    unsigned int			max_write_zeroes_sectors;
    unsigned int			max_hw_sectors;
};

struct bio;

/* We don't use the queue itself, but some of the structure members are used */
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

#define blk_queue_make_request(q, fn)	((q)->make_request_fn = (fn))
#define blk_queue_max_hw_sectors(q, n)	((q)->limits.max_hw_sectors = (n))

extern struct kobj_type blk_queue_ktype;

static inline struct request_queue *
blk_alloc_queue(gfp_t gfp)
{
    struct request_queue * q = record_alloc(q);
    kobject_init(&q->kobj, &blk_queue_ktype);
    INIT_LIST_HEAD(&q->queue_head);
    q->limits.max_hw_sectors = 4*1024*1024;	//XXX
    return q;
}

static inline void
blk_put_queue(struct request_queue * q)
{
    kobject_put(&q->kobj);
}

/* We don't actually use this in the UMC framework,
 * but some fields may be used by apps
 */
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

#define device_put(dev)			kobject_put(&(dev)->kobj);

/*** gendisk ***/

struct block_device;

struct block_device_operations {
    struct module *owner;
    int (*open) (struct block_device *, fmode_t);
    int (*release) (struct gendisk *, fmode_t);
    // int (*rw_page)(struct block_device *, sector_t, struct page *, bool);
    // int (*ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    // int (*compat_ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    // unsigned int (*check_events) (struct gendisk *disk, unsigned int clearing);
};

extern struct list_head UMC_disk_list;
extern spinlock_t UMC_disk_list_lock;

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
#define disk_to_bdev(disk)		((disk)->bdev)

#define get_capacity(disk)		((disk)->part0.nr_sects)

#define set_disk_ro(disk, flag)		((disk)->part0.policy = (flag))

#define disk_stat_read(disk, field)	0   //XXX

/* Partitions not implemented */
#define part_round_stats(cpu, part)	(_USE(cpu), _USE(part))
#define part_stat_inc(a, b, c)		DO_NOTHING()
#define part_stat_add(cpu, prt, tk, dr) DO_NOTHING(_USE(dr))
#define part_stat_read(a, b)		0
#define part_stat_lock()		0
#define part_stat_unlock()		DO_NOTHING()

extern struct gendisk * alloc_disk(int nminors);
extern void del_gendisk(struct gendisk *);

extern void add_disk(struct gendisk *);
extern void put_disk(struct gendisk *);

/*** Block Device ***/

struct block_device {
    struct inode	  * bd_inode;
    struct block_device	  * bd_contains;
    struct gendisk	  * bd_disk;
    unsigned int	    bd_block_size;
    bool		    is_open_exclusive;
};

#define block_size(bdev)		((bdev)->bd_block_size)
#define bdev_size(bdev)			((bdev)->bd_inode->i_size)

#define bdev_get_queue(bdev)		((bdev)->bd_disk->queue)
#define bdev_discard_alignment(bdev)	bdev_get_queue(bdev)->limits.discard_alignment
#define bdevname(bdev, buf) \
	    ({ snprintf((buf), BDEVNAME_SIZE, "%s", (bdev)->bd_disk->disk_name); (buf); })

#define bdev_read_only(bdev)		((bdev)->bd_disk->part0.policy != 0)

static inline void
set_capacity(struct gendisk * disk, sector_t nsectors)
{
    struct fuse_node * fnode = disk->bdev->bd_inode->pde;
    disk->part0.nr_sects = nsectors;
    disk->bdev->bd_inode->i_size = nsectors << 9;
    fuse_node_update_size(fnode, nsectors << 9);
}

extern int blkdev_put(struct block_device *bdev, fmode_t fmode);

/* Take another reference on the bdev */
static inline struct block_device *
bdgrab(struct block_device * bdev)
{
    assert_eq(bdev->bd_inode->UMC_type, I_TYPE_BDEV);
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
extern struct block_device * bdget(dev_t devt);

#define fsync_bdev(bdev)		fsync((bdev)->bd_inode->UMC_fd)	//XXXXX bogus

extern struct block_device * _open_bdev(const char *path, fmode_t fmode);
extern int _close_bdev(struct block_device * bdev, fmode_t fmode);

extern struct block_device * open_bdev_exclusive(const char * path, fmode_t, void * holder);
extern void close_bdev_exclusive(struct block_device * bdev, fmode_t);

extern struct block_device * bdev_complex(const char * diskname, int major, int minor,
					error_t (*mk)(struct request_queue *, struct bio *),
					int blkbits, size_t dev_size);
extern void bdev_complex_free(struct block_device *);

extern void UMC_link_disk_to_bdev(struct gendisk *, struct block_device *);

/*** Block I/O ***/

struct bio_vec {
	struct page     *bv_page;
	unsigned int    bv_len;
	unsigned int    bv_offset;
};

typedef void (bio_end_io_t) (struct bio *, int);
typedef void (bio_destructor_t) (struct bio *);

struct bio {
	sector_t		bi_sector;	/* device address */
	struct bio		*bi_next;	/* request queue link */
	struct block_device	*bi_bdev;
	unsigned long		bi_flags;
	unsigned long		bi_rw;		/* bottom bits READ/WRITE */
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	unsigned short		bi_idx;		/* current index into bvl_vec */
//	unsigned int		bi_phys_segments;
	unsigned int		bi_size;	/* residual I/O count */
//	unsigned int		bi_seg_front_size;
//	unsigned int		bi_seg_back_size;
	unsigned int		bi_max_vecs;	/* max bvl_vecs we can hold */
//	unsigned int		bi_comp_cpu;	/* completion CPU */
	atomic_t		bi_cnt;		/* pin count */
	struct bio_vec		*bi_io_vec;	/* the actual vec list */
	bio_end_io_t		*bi_end_io;
	void			*bi_private;
	bio_destructor_t	*bi_destructor;
	int			bi_error;
	struct bio_vec		bi_inline_vecs[0];  /* KEEP LAST */
};

#define bio_set_dev(bio, bdev)		((bio)->bi_bdev = (bdev))

/* bi_flags */
#define BIO_UPTODATE	    0	/* ok after I/O completion */
//#define BIO_RW_BLOCK	    1	/* RW_AHEAD set, and read/write would block */
#define BIO_EOF		    2	/* out-out-bounds error */
//#define BIO_SEG_VALID	    3	/* bi_phys_segments valid */
#define BIO_CLONED	    4	/* doesn't own data */
//#define BIO_BOUNCED	    5	/* bio is a bounce bio */
//#define BIO_USER_MAPPED   6	/* contains user pages */
//#define BIO_EOPNOTSUPP    7	/* not supported */
//#define BIO_CPU_AFFINE    8	/* complete bio on same CPU as submitted */
//#define BIO_NULL_MAPPED   9	/* contains invalid user pages */
//#define BIO_FS_INTEGRITY 10	/* fs owns integrity data, not block layer */
//#define BIO_QUIET	    11	/* Make BIO Quiet */

//#define BIO_POOL_BITS		(4)
//#define BIO_POOL_NONE		((1UL << BIO_POOL_BITS) - 1)
//#define BIO_POOL_OFFSET	(BITS_PER_LONG - BIO_POOL_BITS)
//#define BIO_POOL_MASK		(1UL << BIO_POOL_OFFSET)
//#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)	

/* bio bi_rw flags
 * bit 0 -- data direction: READ=0, WRITE=1
 * bit 5 -- barrier
 *	Insert a serialization point in the IO queue, forcing previously
 *	submitted IO to be completed before this one is issued.
 * bit 6 -- synchronous I/O hint.
 */
enum bio_rw_flags {
	BIO_RW = 0,
//	BIO_RW_FAILFAST_DEV = 1,
//	BIO_RW_FAILFAST_TRANSPORT = 2,
//	BIO_RW_FAILFAST_DRIVER = 3,
	BIO_RW_FAILFAST = 3,		// scst_vdisk.c
	BIO_RW_AHEAD = 4,		// drbd_wrappers.h
	BIO_RW_BARRIER = 5,		// DRBD rejects this
	BIO_RW_SYNCIO = 6,		// drbd_wrappers.h
	BIO_RW_UNPLUG = 7,		// drbd_wrappers.h
	BIO_RW_META = 8,		// scst_vdisk.c
//	BIO_RW_DISCARD = 9,
//	BIO_RW_NOIDLE = 10,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)   //XXX still in 2.6.26, not 2.6.32
#define BIO_RW_SYNC			BIO_RW_SYNCIO
#endif

#define BIO_RW_RQ_MASK			0xf

#define READ				0
#define WRITE				1
#define REQ_BARRIER			(1u<<BIO_RW_BARRIER)
#define REQ_FUA				0x2000
//#define REQ_FLUSH			0x1000000

// drbd_wrappers.h
#define WRITE_SYNC_PLUG			(WRITE | (1 << BIO_RW_SYNCIO))
#define WRITE_SYNC			(WRITE_SYNC_PLUG | (1 << BIO_RW_UNPLUG))
#define READ_SYNC			(READ | (1 << BIO_RW_SYNCIO) | (1 << BIO_RW_UNPLUG))

static inline bool bio_rw_flagged(struct bio *bio, enum bio_rw_flags flag)
{
	return (bio->bi_rw & (1ul<<flag)) != 0;
}

#define bio_iovec_idx(bio, idx)	(&((bio)->bi_io_vec[(idx)]))
#define bio_iovec(bio)		bio_iovec_idx((bio), (bio)->bi_idx)
#define bio_page(bio)		bio_iovec((bio))->bv_page
#define bio_offset(bio)		bio_iovec((bio))->bv_offset
#define bio_segments(bio)	((bio)->bi_vcnt - (bio)->bi_idx)
#define bio_sectors(bio)	((bio)->bi_size >> 9)

#define bio_has_data(bio)	((bio)->bi_size != 0)
#define bio_empty_barrier(bio)	(bio_rw_flagged(bio, REQ_BARRIER) && !bio_has_data(bio))

#define bio_flagged(bio, bitno)		(((bio)->bi_flags &   (1<<(bitno))) != 0)
#define bio_set_flag(bio, bitno)	(((bio)->bi_flags |=  (1<<(bitno))))
#define bio_clr_flag(bio, bitno)	(((bio)->bi_flags &=~ (1<<(bitno))))

#define BIO_MAX_PAGES			1024

#define UMC_bio_op(bio)			((bio)->bi_rw)	//XXXXX ?
#define op_is_sync(op)			(((op) & REQ_BARRIER) != 0)
#define op_is_write(op)			(((op) & WRITE) != 0)
#define bio_data_dir(bio)		(op_is_write(UMC_bio_op(bio)) ? WRITE : READ)
#define bio_get_nr_vecs(bdev)		BIO_MAX_PAGES

#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);  \
	     i < (bio)->bi_vcnt;					\
	     bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

static inline sector_t
blk_rq_pos(const struct request *rq)
{
    return rq->bio ? rq->bio->bi_sector : 0;
}

struct bio_set;
extern void bio_free(struct bio *bio, struct bio_set *bs);
extern void bio_destructor(struct bio *);

#define bio_get(bio)			atomic_inc(&(bio)->bi_cnt)

static inline void
bio_put(struct bio * bio)
{
    if (!atomic_dec_and_test(&bio->bi_cnt))
	return;

    if (bio->bi_destructor)
	bio->bi_destructor(bio);
    else
	bio_destructor(bio);
}

extern struct bio * bio_alloc(gfp_t gfp, unsigned int maxvec);
extern struct bio * bio_clone(struct bio * bio, gfp_t gfp);

#define bio_kmalloc(gfp, maxvec)	bio_alloc((gfp), (maxvec))

static inline void
__bio_add_page(struct bio *bio, struct page *page, unsigned int len, unsigned int off)
{
    struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

    WARN_ONCE(bio_flagged(bio, BIO_CLONED), "adding pages to a cloned bio\n");
    assert_lt(bio->bi_vcnt, bio->bi_max_vecs);

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

extern void bio_endio(struct bio * bio, error_t err);

/* Compatibility macros in DRBD too complicated to explain here, but */
/* Don't waste time trying to merge these next ones. */
static inline error_t
submit_bio(int rw, struct bio * bio)
{
    bio->bi_rw |= rw;
    WARN_ONCE(!bio->bi_end_io, "submit_bio() got a bio with no endio function");
    return bio->bi_bdev->bd_disk->queue->make_request_fn(bio->bi_bdev->bd_disk->queue, bio);
}

static inline error_t
_submit_bio(struct bio * bio)
{
    return bio->bi_bdev->bd_disk->queue->make_request_fn(bio->bi_bdev->bd_disk->queue, bio);
}

#define generic_make_request(bio)	_submit_bio(bio)

/******************************************************************************/

struct bio_set				{ };	    /* bio_set not implemented */
#define BIO_POOL_SIZE			IGNORED	    /* bio_set */

#define bioset_integrity_create(bioset, x) (-ENOTSUP)

static inline struct bio_set *
bioset_create(unsigned int pool_size, unsigned int front_pad)
{
    return (struct bio_set *)(-1);  /* XXX non-NULL fakes success, will be otherwise unused */
}

static inline void
bioset_free(struct bio_set * bs)
{
    assert_eq(bs, (struct bio_set *)(-1));
}

static inline struct bio *
bio_alloc_bioset(gfp_t gfp, unsigned int n, struct bio_set * bs)
{
    assert_eq(bs, (struct bio_set *)(-1));
    return bio_alloc(gfp, n);
}

/******************************************************************************/

typedef u8				blk_status_t;

#define BLK_STS_OK		0
#define BLK_STS_NOTSUPP		1
#define BLK_STS_MEDIUM		7
#define BLK_STS_RESOURCE	9
#define BLK_STS_IOERR		10

#define blk_cleanup_queue(q)		blk_put_queue(q)

#define blk_bidi_rq(rq)                ((rq)->next_rq != NULL)

/* PDU allocated immediately beyond the request structure */
static inline void *
blk_mq_rq_to_pdu(struct request *rq)
{
	return rq + 1;
}

#define BDEVNAME_SIZE		32	/* Largest string for a blockdev identifier */

#define blkdev_issue_flush(bdev, x)		fsync_bdev(bdev)    //XXXXX right?

/******************************************************************************/

#define queue_flag_clear(bit, q)	clear_bit((bit), &(q)->queue_flags)
#define queue_flag_set(bit, q)		set_bit((bit), &(q)->queue_flags)
#define queue_max_hw_sectors(q)		((q)->limits.max_hw_sectors)
#define queue_alignment_offset(a)	0
#define queue_io_min(a)			PAGE_SIZE
#define queue_io_opt(a)			PAGE_SIZE

#define queue_dma_alignment(q)		511
#define queue_logical_block_size(q)	512

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define queue_physical_block_size(a)	4096	//XXXX
#endif

struct blk_plug_cb { void *data; };
struct blk_plug { };

#define blk_queue_max_discard_sectors(q, n) DO_NOTHING()    /* set no max */
#define blk_queue_segment_boundary(q, mask) DO_NOTHING()    /* set no rules */
#define blk_queue_stack_limits(q1, q2)	DO_NOTHING()	    /* no extra limits */
#define blk_set_stacking_limits(a)	DO_NOTHING()	    /* set no limits */
#define blk_check_plugged(a, b, c)	NULL		    /* no plug */
#define blk_finish_plug(a)		DO_NOTHING()	    /* no plug */
#define blk_start_plug(a)		DO_NOTHING()	    /* no plug */

/* Add request to queue for execution (unused) */
#define blk_execute_rq_nowait(q, disk, rq, at_head, done_fn) \
	    UMC_STUB(blk_execute_rq_nowait);

#define register_blkdev(major, name)		0
#define unregister_blkdev(major, name)		DO_NOTHING()

#define blkdev_issue_discard(bdev, sector, nr_sects, gfp, flags)    (-EOPNOTSUPP)

#define bd_link_disk_holder(a, b)	0			//XXX
#define bd_unlink_disk_holder(a, b)	DO_NOTHING()		//XXX

#define bd_claim_by_disk(bde, claim_ptr, vdisk)	0		//XXX
#define bd_release_from_disk(bde, vdisk)	DO_NOTHING()	//XXX

#endif /* UMC_BIO_H */
