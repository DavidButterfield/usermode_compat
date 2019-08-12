/* UMC_inode.h -- Usermode compatibility: inodes and files
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_INODE_H
#define UMC_INODE_H
#include "UMC_sys.h"
#include "UMC_lock.h"
#include "fuse_tree.h"
#include <sys/stat.h>	    // umode_t, off_t, dev_t	//XXX

struct inode {
    /* set by init_inode() */
    int				UMC_type;	/* I_TYPE_* */
    int				UMC_fd;		/* backing usermode real fd */
    atomic_t			i_count;	/* refcount */
    umode_t			i_mode;		/* e.g. S_ISREG */
    off_t			i_size;		/* device or file size in bytes */
    unsigned int		i_flags;	/* O_RDONLY, O_RDWR */
    struct mutex		i_mutex;
    time_t			i_atime;
    time_t			i_mtime;
    time_t			i_ctime;

    struct block_device	      * i_bdev;		/* when I_TYPE_BDEV */
    unsigned int		i_blkbits;	/* log2(block_size) */
    dev_t			i_rdev;		/* device major/minor */

    struct proc_dir_entry     * pde;		/* when I_TYPE_PROC */

    void			(*UMC_destructor)(struct inode *);

    /* unused */
//  unsigned long		i_ino;
//  unsigned int		i_nlink;
//  blkcnt_t			i_blocks;
//  void		      *	i_private;
};

#define I_TYPE_FILE			1   /* real file or real block device */
#define I_TYPE_SOCK			2   /* real socket */
#define I_TYPE_PROC			3   /* /proc thing */
#define I_TYPE_BDEV			4   /* UMC internal block device */

#define BDEV_I(inode)			({ assert_eq((inode)->UMC_type, I_TYPE_BDEV); \
					   (inode)->i_bdev; \
					})

#define i_size_read(inode)		((inode)->i_size)

static inline void
init_inode(struct inode * inode, int type, umode_t mode,
			size_t size, unsigned int oflags, int fd)
{
    record_zero(inode);
    inode->UMC_type = type;
    inode->UMC_fd = fd;
    atomic_set(&inode->i_count, 1);
    inode->i_mode = mode;
    inode->i_size = size;
    inode->i_flags = oflags;
    mutex_init(&inode->i_mutex);
    inode->i_atime = inode->i_mtime = inode->i_ctime = sys_time_delta_to_sec(sys_time_now());
}

static inline void
_iget(struct inode * inode)
{
    assert_ne(inode, 0);
    atomic_inc(&inode->i_count);
}

static inline void
iput(struct inode * inode)
{
    assert_ne(inode, 0);
    if (!atomic_dec_and_test(&inode->i_count))
	return;

    mutex_destroy(&inode->i_mutex);

    if (inode->UMC_destructor)
	inode->UMC_destructor(inode);
    else
	record_free(inode);
}

#endif /* UMC_INODE_H */
