/* fuse_bio.c -- translate fuse_node_ops into bio operations
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * This provides an interface from a fuse_tree into a bio implementor.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>

#include "UMC_bio.h"
#include "UMC_thread.h"
#include "fuse_tree.h"
#include "fuse_tcmur.h"

#define trace_bio(args...)		//	printk(args)

static error_t
fuse_bio_open(fuse_node_t fnode, uintptr_t bdev_uip)
{
    struct block_device * bdev = (struct block_device *)bdev_uip;
    return bdev->bd_disk->fops->open(bdev, bdev->bd_inode->i_mode);
}

static error_t
fuse_bio_release(fuse_node_t fnode, uintptr_t bdev_uip)
{
    struct block_device * bdev = (struct block_device *)bdev_uip;
    bdev->bd_disk->fops->release(bdev->bd_disk, bdev->bd_inode->i_mode);
    return 0;
}

static void
fuse_bio_endio(struct bio * bio, error_t err)
{
    bio->bi_error = err;
    complete((struct completion *)bio->bi_private);
}

static ssize_t
_fuse_bio_io(struct block_device * bdev, void * buf, size_t iosize, off_t ofs, int rwf)
{
    struct bio * bio;
    char * p = buf;
    size_t size = iosize;
    off_t page_off;

    unsigned int npage = 2 + (unsigned int)(iosize / PAGE_SIZE);
    struct page pages[npage];
    struct page * page = &pages[0];
    memset(pages, 0, sizeof(pages));

    assert_imply(iosize, buf);
    assert_eq(ofs % 512, 0, "EINVAL unaligned offset on minor %d",
				bdev->bd_disk->first_minor);
    assert_eq(iosize % 512, 0, "EINVAL unaligned iosize on minor %d",
				bdev->bd_disk->first_minor);
//  assert_eq((uintptr_t)buf % 512, 0, "EINVAL unaligned buffer on minor %d", minor);
//  if ((uintptr_t)buf % 512)
//	return -EINVAL;

    bio = bio_alloc(0, npage);
    bio_set_dev(bio, bdev);
    bio->bi_sector = ofs >> 9;
    bio->bi_end_io = fuse_bio_endio;

    /* Compute start offset in first page */
    page_off = offset_in_page(p);
    assert_lt(page_off, PAGE_SIZE);

    /* Fill in the bio page list with the pages of the buffer */
    while (size) {
	size_t page_datalen = min((size_t)(PAGE_SIZE - page_off), size);
	assert_lt(page, pages + npage);
	page->vaddr = (void *)((uintptr_t)p & PAGE_MASK);
	page->order = 1;
	bio_add_page(bio, page, (unsigned int)page_datalen, (unsigned int)page_off);
	p += page_datalen;
	size -= page_datalen;
	page++;
	page_off = 0;	/* non-first pages start at offset zero */
    }

    assert_eq(bio->bi_size, iosize);

    /* Issue the I/O and wait for it to complete */
    {
	ssize_t ret;
	struct completion c;
	init_completion(&c);
	bio->bi_private = (void *)&c;

	ret = submit_bio(rwf, bio);
	if (!ret) {
	    wait_for_completion(&c);
	    ret = bio->bi_error;
	}

	assert_le(bio->bi_size, iosize);

	if (ret == 0)
	    ret = iosize - bio->bi_size;    /* done = requested - residual */

	bio_put(bio);

	return ret;
    }
}

static ssize_t
fuse_bio_io(struct block_device * bdev, char * buf, size_t iosize, off_t ofs, int rwf)
{
    ssize_t ret;
    /* Handle bogus partial sector I/O coming even when using kernel buffer cache */
    //XXXX could copy only the first and/or last block; we process pages separately above...
    size_t align = 1u << bdev->bd_inode->i_blkbits;
    off_t end = ofs + iosize;
    bool is_write = op_is_write(rwf);

    off_t adj_ofs;
    off_t adj_end;
    ssize_t adj_iosize;
    char * adj_buf;

    if (ofs % align || iosize % align) {
	adj_ofs = ofs / align * align;
	adj_end = (end + align - 1) / align * align;
	adj_iosize = adj_end - adj_ofs;
	adj_buf = vmalloc(adj_iosize);
	if (is_write) {
	    trace_bio("READ BEFORE WRITE: (minor %d) %ld @%ld", (int)minor, adj_iosize, adj_ofs);
	    ret = _fuse_bio_io(bdev, adj_buf, adj_iosize, adj_ofs, READ);
	    memcpy(adj_buf + ofs - adj_ofs, buf, iosize);
	}
    } else {
	adj_ofs = ofs;
	adj_end = end;
	adj_iosize = iosize;
	adj_buf = buf;
    }

    ret = _fuse_bio_io(bdev, adj_buf, adj_iosize, adj_ofs, rwf);
    if (ret >= 0 && ret != adj_iosize)
	ret = -EIO;

    if (adj_buf != buf) {
	if (!is_write && ret > 0) {
	    memcpy(buf, adj_buf + ofs - adj_ofs, iosize);
	}
	vfree(adj_buf);
    }

    return ret < 0 ? ret : (ssize_t)iosize;
}

static ssize_t
fuse_bio_read(uintptr_t bdev_uip, void * buf, size_t iosize, off_t ofs)
{
    struct block_device * bdev = (struct block_device *)bdev_uip;
    ssize_t ret = fuse_bio_io(bdev, buf, iosize, ofs, READ);
    if (ret < 0)
	pr_warning("READ FAILED %ld: (minor %d) %ld @%ld\n",
		    ret, bdev->bd_disk->first_minor, iosize, ofs);
    return ret;
}

static ssize_t
fuse_bio_write(uintptr_t bdev_uip, const char * buf, size_t iosize, off_t ofs)
{
    struct block_device * bdev = (struct block_device *)bdev_uip;
    ssize_t ret = fuse_bio_io(bdev, _unconstify(buf), iosize, ofs, WRITE);
    if (ret < 0)
	pr_warning("WRITE FAILED %ld: (minor %d) %ld @%ld\n",
		    ret, bdev->bd_disk->first_minor, iosize, ofs);
    return ret;
}

static error_t
fuse_bio_fsync(uintptr_t bdev_uip, int datasync)
{
    struct block_device * bdev = (struct block_device *)bdev_uip;
    ssize_t ret = _fuse_bio_io(bdev, NULL, 0, 0, BIO_RW_BARRIER);
    assert_le(ret, 0);
    if (ret < 0)
	pr_warning("FSYNC FAILED %ld: (minor %d)\n",
		    ret, bdev->bd_disk->first_minor);
    return (error_t)ret;
}

struct fuse_node_ops fuse_bio_ops = {
    .open = fuse_bio_open,
    .release = fuse_bio_release,
    .read = fuse_bio_read,
    .write = fuse_bio_write,
    .fsync = fuse_bio_fsync,
};

error_t
fuse_bio_init(void)
{
    return fuse_tcmur_ctl_init(&fuse_bio_ops);
}

error_t
fuse_bio_exit(void)
{
    return fuse_tcmur_ctl_exit();
}