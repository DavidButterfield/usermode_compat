/* bio_tcmur.c -- translate bio operations into tcmu-runner handler calls
 *
 * Copyright (c) 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * bio_tcmur translates bio requests into libtcmur requests.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#include "UMC_bio.h"
#include "fuse_tree.h"
#include "libtcmur.h"

static int bio_tcmur_major;
static struct kmem_cache * op_cache;
static struct block_device ** the_bio_tcmur_bdevs;
static int n_bio_tcmur_bdevs;

#define bdev_to_minor(bdev) ((bdev)->bd_disk->first_minor)

#define bdev_of_minor(minor) \
    ((minor) < n_bio_tcmur_bdevs ? the_bio_tcmur_bdevs[minor] : NULL)

struct block_device *
bio_tcmur_bdev(int minor)
{
    return bdev_of_minor(minor);
}

#define MAX_FAST_IOV 16
struct bio_tcmur_op {
	struct tcmur_cmd cmd;
	struct bio * bio;
	struct iovec iov_space[MAX_FAST_IOV];
};

#define op_of_cmd(cmd)	container_of((cmd), struct bio_tcmur_op, cmd)

/* Complete the bio to our client */
static inline void
io_done(struct bio * bio, error_t err)
{
    bio_endio(bio, err);
}

/* Reply from tcmu-runner handler */
static void
io_done_sts(struct tcmu_device * tcmu_dev,
	    struct tcmur_cmd * cmd, tcmur_status_t sts)
{
    struct bio_tcmur_op * op = op_of_cmd(cmd);
    struct bio * bio = op->bio;
    error_t err = 0;

    /* Translate tcmur_status_t to -errno */
    if (sts != TCMU_STS_OK)
	err = -EIO;

    io_done(bio, err);

    if (cmd->iovec && cmd->iovec != op->iov_space)
	vfree(cmd->iovec);

    kmem_cache_free(op_cache, op);
}

static error_t make_request(struct request_queue *, struct bio *);

static void
io_continue(struct tcmu_device * tcmu_dev,
	    struct tcmur_cmd * cmd, tcmur_status_t sts)
{
    struct bio_tcmur_op * op = op_of_cmd(cmd);
    struct bio * bio = op->bio;

    if (sts != TCMU_STS_OK)
	io_done_sts(tcmu_dev, cmd, sts);
    else {
	bio->bi_rw &= ~REQ_BARRIER;
	make_request(NULL, bio);
	assert_eq(cmd->iovec, 0);	/* the fsync had no iovec */
	kmem_cache_free(op_cache, op);
    }
}

/* Early reply due to error */
static void
io_done_err(struct bio * bio, error_t err)
{
    io_done(bio, err);
}

/* Receive a bio request from our client */
static error_t
make_request(struct request_queue *rq_unused, struct bio * bio)
{
    error_t err;
    size_t cmdlen = 0;
    
    bool is_sync = op_is_sync(UMC_bio_op(bio));
    bool is_write = op_is_write(UMC_bio_op(bio));

    struct bio_tcmur_op * op;
    struct tcmur_cmd * cmd;

    struct gendisk * disk = bio->bi_bdev->bd_disk;

    unsigned short niov = bio->bi_vcnt;
    unsigned short iovn = bio->bi_idx;	    //XXX right?

    int minor = disk->first_minor;

    uint64_t seekpos = bio->bi_sector << 9;
    ssize_t dev_size = tcmur_get_size(minor);
    if (dev_size < 0) {
	err = (error_t)dev_size;	    /* -errno */
	goto out_finish;
    }

    #define BITS_OK ((1ul<<BIO_RW_FAILFAST)|(1ul<<BIO_RW_META)|(1ul<<BIO_RW_AHEAD) \
		    |(1ul<<BIO_RW_SYNCIO)|(1ul<<BIO_RW_UNPLUG)|(1ul<<BIO_RW_BARRIER))
    expect_eq(bio->bi_rw & ~(WRITE|BITS_OK), 0,
		"Unexpected bi_rw bits 0x%lx/0x%lx",
		bio->bi_rw & ~(WRITE|BITS_OK), bio->bi_rw);

    op = kmem_cache_zalloc(op_cache, 0);
    if (!op)
	return -ENOMEM;

    op->bio = bio;

    cmd = &op->cmd;
    cmd->done = io_done_sts;

    if (is_sync) {
	if (!bio_empty_barrier(bio))
	    cmd->done = io_continue;
	err = tcmur_flush(minor, cmd);
	if (err)
	    io_done_err(bio, err);
	return err;
    }

    if (seekpos >= (size_t)dev_size) {
	bio_set_flag(bio, BIO_EOF);
	pr_warning("attempt to seek minor %d (%s) to %lu outside bound %lu\n",
	    minor, tcmur_get_dev_name(minor), seekpos, tcmur_get_size(minor));
	err = -EINVAL;		//XXX right?
	goto out_finish;
    }

    if (seekpos + bio->bi_size > (size_t)dev_size)
	bio->bi_size = (unsigned int)(dev_size - seekpos);	//XXX right?

    if (niov <= ARRAY_SIZE(op->iov_space))
	cmd->iovec = op->iov_space;
    else
	cmd->iovec = vzalloc(niov * sizeof(struct iovec));

    /* Translate the segments of the bio data I/O buffer into iovec entries,
     * coalescing adjacent buffer segments.  (It is OK that coalescing means we
     * might not use all of the iovec array)
     */
    while (bio->bi_idx < bio->bi_vcnt) {
	size_t seglen = bio->bi_io_vec[bio->bi_idx].bv_len; /* get next sg segment */
	uint8_t * segaddr = (uint8_t *)bio->bi_io_vec[bio->bi_idx].bv_page->vaddr
				+ bio->bi_io_vec[bio->bi_idx].bv_offset;

	if (iovn > 0 && segaddr == (uint8_t *)cmd->iovec[iovn-1].iov_base
					    + cmd->iovec[iovn-1].iov_len) {
	    cmd->iovec[iovn-1].iov_len += seglen;    /* coalesce with previous entry */
	} else {
	    assert_lt(iovn, niov, "iovn=%d niov=%d", iovn, niov);
	    cmd->iovec[iovn].iov_base = segaddr;	    /* fill in a new entry */
	    cmd->iovec[iovn].iov_len = seglen;
	    ++iovn;
	}
	cmdlen += seglen;
	++bio->bi_idx;
    }

    assert_eq(cmdlen, bio->bi_size);
    assert_eq(cmdlen % 512, 0);
    assert_eq(seekpos % 512, 0);

    cmd->iov_cnt = iovn;		    /* number of iovec elements we filled in */

    /* Submit the command to the handler */
    if (is_write) {
	err = tcmur_write(minor, cmd, cmd->iovec, cmd->iov_cnt, cmdlen, seekpos);
    } else {
	err = tcmur_read(minor, cmd, cmd->iovec, cmd->iov_cnt, cmdlen, seekpos);
    }

    if (!err)
	return 0;

out_finish:
    io_done_err(bio, err);
    return err;		    //XXX Right?
}

static int
bio_tcmur_open(struct block_device * bdev, fmode_t fmode)
{
    return 0;
}

static int
bio_tcmur_release(struct gendisk * disk, fmode_t fmode)
{
    return 0;
}

struct block_device_operations bio_tcmur_ops = {
    .open = bio_tcmur_open,
    .release = bio_tcmur_release,
};

static bool bio_enabled;

/* Add a new tcmur bdev at minor */
error_t
bio_tcmur_add(int minor)
{
    struct block_device * bdev;
    size_t size;
    size_t block_size;
    int blkbits;

    if (!bio_enabled)
	return 0;	/* not enabled -- successfully do nothing */

    if (minor >= n_bio_tcmur_bdevs)
	return -EINVAL;

    if (bdev_of_minor(minor))
	return -EBUSY;

    size = tcmur_get_size(minor);
    block_size = tcmur_get_block_size(minor);
    blkbits = ilog2(block_size);

    pr_notice("bio_tcmur_add minor=%d size=%ld blkbits=%d block_size=%ld\n",
		minor, size, blkbits, block_size);

    if (block_size != 1u << blkbits) {
	pr_err("%s: bad block size=%ld not a power of two (%d)\n",
			    tcmur_get_dev_name(minor), block_size, blkbits);
	return -EINVAL;
    }

    if (block_size < 512 || block_size > UINT_MAX) {
	pr_err("%s: bad block size=%ld\n",
			    tcmur_get_dev_name(minor), block_size);
	return -EINVAL;
    }

    if (size < block_size) {
	pr_err("%s: bad device size=%"PRIu64"\n",
			    tcmur_get_dev_name(minor), size);
	return -EINVAL;
    }

    bdev = bdev_complex(tcmur_get_dev_name(minor), bio_tcmur_major, minor,
			make_request, blkbits, size);

    bdev->bd_disk->fops = &bio_tcmur_ops;

    set_capacity(bdev->bd_disk, size>>9);

    the_bio_tcmur_bdevs[minor] = bdev;
    return 0;
}

/* Remove the bdev at the tcmur minor */
error_t
bio_tcmur_remove(int minor)
{
    struct block_device * bdev = bdev_of_minor(minor);
    if (!bdev)
	return -ENOENT;

    //XXXXX bio_tcmur_remove() needs to check refcount or use iput or something

    bdev_complex_free(bdev);
    the_bio_tcmur_bdevs[minor] = NULL;
    return 0;
}

/* Call to enable creation of a bio-style bdev.  If this function is not
 * called, then minors will be created with fuse nodes but no bio interface.
 */
error_t
bio_tcmur_init(int major, int max_minor)
{
    assert_eq(bio_enabled, 0);		    /* double init */
    assert_gt(max_minor, 0);
    assert_eq(the_bio_tcmur_bdevs, NULL);
    assert_eq(n_bio_tcmur_bdevs, 0);

    op_cache = kmem_cache_create(
			"the_bio_tcmur_op_cache",
			sizeof(struct bio_tcmur_op),
			0,	/* use default alignment */
			0,	/* gfp */
			0);	/* constructer */
    if (!op_cache)
	return -ENOMEM;

    the_bio_tcmur_bdevs = vzalloc(max_minor * sizeof(*the_bio_tcmur_bdevs));
    if (!the_bio_tcmur_bdevs) {
	kmem_cache_destroy(op_cache);
	op_cache = NULL;
	return -ENOMEM;
    }

    n_bio_tcmur_bdevs = max_minor;

    bio_enabled = true;
    return 0;
}

error_t
bio_tcmur_exit(void)
{
    int i;
    assert(bio_enabled);		/* not initialized */
    assert(the_bio_tcmur_bdevs);
    assert(n_bio_tcmur_bdevs);
    assert(op_cache);

    for (i = 0; i < n_bio_tcmur_bdevs; i++)
	if (the_bio_tcmur_bdevs[i])
	    return -EBUSY;

    bio_enabled = false;

    vfree(the_bio_tcmur_bdevs);
    the_bio_tcmur_bdevs = NULL;
    n_bio_tcmur_bdevs = 0;

    kmem_cache_destroy(op_cache);
    op_cache = NULL;

    return 0;
}
