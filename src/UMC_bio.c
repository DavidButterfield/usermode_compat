/* UMC_bio.c -- Usermode compatibility: block I/O
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#define _GNU_SOURCE
#include "UMC_bio.h"

#define trace_bdev(fmtargs...)		printk(fmtargs)

LIST_HEAD(UMC_pagelist);		/* list for struct page */
DEFINE_SPINLOCK(UMC_pagelist_lock);

uint8_t __aligned(PAGE_SIZE) empty_zero_page[PAGE_SIZE];
struct page zero_page;

const char * UMC_fuse_mount_point = "/tcmur";	//XXXXXX

static void
bdev_inode_destructor(struct inode * inode)
{
    assert_eq(inode->UMC_fd, -1);
    record_free(BDEV_I(inode));
    record_free(inode);
}

struct block_device *
bdget(dev_t devt)
{
    struct block_device * bdev = record_alloc(bdev);
    struct inode * inode = record_alloc(inode);

    init_inode(inode, I_TYPE_BDEV, S_IFBLK, 0/*size*/, 0, -1);
    inode->UMC_destructor = bdev_inode_destructor;
    inode->i_bdev = bdev;
    inode->i_rdev = devt;
    inode->i_blkbits = 12;	//XXXX

    bdev->bd_inode = inode;
    bdev->bd_block_size = (1 << inode->i_blkbits);

    return bdev;
}

/* Expects full internal pathnames like "/UMCfuse/dev/drbd1".
 * Grabs a reference if device is found and exclusivity is OK.
 */
static struct block_device *
lookup_bdev(const char * path, bool exclusive)
{
    struct block_device * bdev = NULL;
    struct gendisk * pos;
    const char *p;

    static char prefix[64];
    if (!*prefix)
	snprintf(prefix, sizeof(prefix), "%s/dev/", UMC_fuse_mount_point);

    if (strncmp(path, prefix, strlen(prefix))) {
	pr_warning("Bad device name prefix: %s\n", path);
	return NULL;
    }

    p = path + strlen(prefix);	/* skip prefix to name under /dev */

    spin_lock(&UMC_disk_list_lock);

    list_for_each_entry(pos, &UMC_disk_list, disk_list)
	if (!strcmp(pos->disk_name, p)) {
	    bdev = disk_to_bdev(pos);
	    assert_ne(bdev, NULL);
	    break;
	}

    if (bdev) {
	if (bdev->is_open_exclusive)
	    bdev = ERR_PTR(-EBUSY);
	else if (exclusive && atomic_get(&bdev->bd_inode->i_count) > 1)
	    bdev = ERR_PTR(-EBUSY);
	else {
	    bdev->is_open_exclusive = exclusive;
	    bdgrab(bdev);
	}
    } else
	bdev = ERR_PTR(-ENOENT);

    spin_unlock(&UMC_disk_list_lock);

    return bdev;
}

struct block_device *
_open_bdev(const char *path, fmode_t fmode)
{
    struct block_device *bdev;
    bool want_exclusive = !!(fmode & FMODE_EXCL);

    bdev = lookup_bdev(path, want_exclusive);
    if (IS_ERR(bdev)) {
	    trace_err("****************** bdev %s err=%ld", path, PTR_ERR(bdev));
	    return bdev;
    }

    if ((fmode & FMODE_WRITE) && bdev_read_only(bdev)) {
	    trace_err("****************** bdev %s says it is readonly", path);
	    bdput(bdev);
	    return ERR_PTR(-EACCES);	//XXX -EROFS ?
    }

    assert_eq(bdev->bd_contains, bdev);	    /* no partitions */
    assert_ne(bdev->bd_disk, NULL);
    assert_ne(bdev->bd_disk->fops, NULL);
    assert_ne(bdev->bd_disk->fops->open, NULL);
    assert_ne(bdev->bd_disk->fops->release, NULL);

    int error = bdev->bd_disk->fops->open(bdev, fmode);
    if (error) {
	pr_warning("****************** bdev %s failed fops->open() %d\n", path, error);
	bdput(bdev);
	return ERR_PTR(error);
    }

    trace_bdev("name='%s' size=%"PRIu64, bdev->bd_disk->disk_name, bdev_size(bdev));

    return bdev;
}

/* Returns pointer to bdev, or an ERR_PTR */
struct block_device *
open_bdev_exclusive(const char *path, fmode_t fmode, void *holder)
{
    fmode |= FMODE_EXCL;
    return _open_bdev(path, fmode);
}

void
close_bdev_exclusive(struct block_device *bdev, fmode_t fmode)
{
    assert_eq(bdev->bd_contains, bdev);
    assert_ne(bdev->bd_disk, NULL);
    assert_ne(bdev->bd_disk->fops, NULL);
    expect_ne(bdev->bd_disk->fops->release, NULL);

    trace_bdev("name='%s' size=%"PRIu64, bdev->bd_disk->disk_name, bdev_size(bdev));

    fmode |= FMODE_EXCL;

    if (bdev->bd_disk->fops->release)
	bdev->bd_disk->fops->release(bdev->bd_disk, fmode);

    bdput(bdev);	/* --refcount */
}

struct gendisk *
alloc_disk(int nminors)
{
    struct gendisk * disk = record_alloc(disk);
    assert_eq(nminors, 1);		//XXX Limitation
    disk->part0.__dev = device_alloc();
    disk->part0.__dev->disk = disk;
    return disk;
}

void
put_disk(struct gendisk * disk)
{
    kobject_put(&disk_to_dev(disk)->kobj);
}

/* Remove the disk from the globally-visible disk list */
void
del_gendisk(struct gendisk * disk)
{
    spin_lock(&UMC_disk_list_lock);
    list_del(&disk->disk_list);		/* remove from UMC_disk_list */
    spin_unlock(&UMC_disk_list_lock);
    /* put_disk() occurs in a separate call */
}

/* Add the disk to the globally-visible disk list */
void
add_disk(struct gendisk * disk)
{
    dev_t devt = MKDEV(disk->major, disk->first_minor);
    struct device *dev = disk_to_dev(disk);
    dev->devt = devt;
    dev->parent = NULL;
    spin_lock(&UMC_disk_list_lock);
    list_add(&disk->disk_list, &UMC_disk_list);
    spin_unlock(&UMC_disk_list_lock);
}

/* Create a collection of structures surrounding a bdev */
struct block_device *
bdev_complex(const char * diskname, int major, int minor,
		error_t (*mk)(struct request_queue *, struct bio *))
{
    struct device * dev;
    struct block_device *bdev;
    struct gendisk * disk = alloc_disk(1);  /* allocates gendisk and dev */
    disk->major = major;
    disk->first_minor = minor;
    memcpy(disk->disk_name, diskname, sizeof(disk->disk_name)-1);

    disk->queue = blk_alloc_queue(0);
    disk->queue->make_request_fn = mk;

    add_disk(disk);		/* sets dev->devt */

    dev = disk_to_dev(disk);
    bdev = bdget(dev->devt);	/* creates bdev and inode */
    bdev->bd_contains = bdev;

    disk_to_bdev(disk) = bdev;
    disk_to_bdev(disk)->bd_disk = disk;

    return bdev;
}

void
bdev_complex_free(struct block_device * bdev)
{
    del_gendisk(bdev->bd_disk);			/* remove disk from list */
    blk_put_queue(bdev->bd_disk->queue);	/* drop request queue */
    put_disk(bdev->bd_disk);			/* drop disk and dev */
    bdput(bdev);				/* drop bdev and inode */
}

static inline void
bio_free(struct bio *bio, struct bio_set *bs)
{
    assert_eq(bs, NULL);
    assert_eq(atomic_read(&bio->bi_cnt), 0);
    kfree(bio);
}

void
bio_destructor(struct bio *bio)
{
    bio_free(bio, NULL);
}

struct bio *
bio_alloc(gfp_t gfp, unsigned int maxvec)
{
    struct bio * bio;
    bio = kzalloc(sizeof(struct bio) + maxvec * sizeof(struct bio_vec), gfp);
    bio->bi_io_vec = (struct bio_vec *)(bio+1);
    bio->bi_max_vecs = maxvec;
    bio->bi_destructor = bio_destructor;
    bio_set_flag(bio, BIO_UPTODATE);
    atomic_set(&bio->bi_cnt, 1);
    return bio;
}

struct bio *
bio_clone(struct bio * bio, gfp_t gfp)
{
    struct bio * new_bio = bio_alloc(gfp, bio->bi_max_vecs);
    new_bio->bi_bdev	= bio->bi_bdev;
    new_bio->bi_vcnt	= bio->bi_vcnt;
    new_bio->bi_idx	= bio->bi_idx;
    new_bio->bi_size	= bio->bi_size;
    new_bio->bi_sector	= bio->bi_sector;
    new_bio->bi_rw	= bio->bi_rw;
    new_bio->bi_flags	= bio->bi_flags;

    memcpy(new_bio->bi_io_vec, bio->bi_io_vec, new_bio->bi_vcnt * sizeof(*new_bio->bi_io_vec));

    new_bio->bi_destructor = bio_destructor;
    atomic_set(&new_bio->bi_cnt, 1);
    bio_set_flag(bio, BIO_CLONED);

    return new_bio;
}

void
bio_endio(struct bio * bio, error_t err)
{
    if (err)
	bio_clr_flag(bio, BIO_UPTODATE);
    else if (!bio_flagged(bio, BIO_UPTODATE))
	err = -EIO;

    if (!err) {
	bio->bi_sector += bio->bi_size >> 9;
	bio->bi_size = 0;	/* resid */
    }

    if (bio->bi_end_io)
	bio->bi_end_io(bio, err);
}

LIST_HEAD(UMC_disk_list);		/* list of struct gendisk */
spinlock_t UMC_disk_list_lock;

static void
blk_queue_release(struct kobject *kobj)
{
    struct request_queue * q = container_of(kobj, struct request_queue, kobj);
    record_free(q);
}

static struct attribute *default_blk_queue_attrs[] = { };

struct kobj_type blk_queue_ktype = {
	.default_attrs  = default_blk_queue_attrs,
	.release	= blk_queue_release,
};

static void
device_release(struct kobject *kobj)
{
    struct device * dev = container_of(kobj, struct device, kobj);
    record_free(dev->disk);
    record_free(dev);
}

static struct attribute *default_device_attrs[] = { };

struct kobj_type device_ktype = {
	.default_attrs  = default_device_attrs,
	.release	= device_release,
};
