/* UMC_file.h -- usermode compatibility for struct file
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_FILE_H
#define UMC_FILE_H
#include "UMC_sys.h"
#include "UMC_inode.h"
#include "UMC_bio.h"
#include <fcntl.h>	    // open, O_*, etc

#define trace_file(fmtargs...)	    //	nlprintk(fmtargs)

#define S_IRUGO				(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO				(S_IWUSR|S_IWGRP|S_IWOTH)

struct file {
//  struct kref			kref;		//XXX no dup(2) emulation
    void		      * private_data;	/* e.g. seq_file */
    struct inode	      * inode;
    fmode_t			f_openmode;
    struct address_space      * f_mapping;	/* ignored by sync_page_range */
//  struct dentry	      * f_dentry;
//  struct file_ra_state	f_ra;
};

#define file_inode(file)		((file)->inode)
#define file_pde(file)			(file_inode(file)->pde)
#define file_pde_data(file)		(file_pde(file)->data)

#define file_accessed(filp)		DO_NOTHING()

struct file_operations {
    void	  * owner;
    int		 (* open)(struct inode *, struct file *);
    int		 (* release)(struct inode * unused, struct file *);
    long	 (* compat_ioctl)  (struct file *, unsigned int cmd, unsigned long);
    long	 (* unlocked_ioctl)(struct file *, unsigned int cmd, unsigned long);
    ssize_t	 (* write)(struct file *, const char * buf, size_t len, loff_t * ofsp);
    ssize_t	 (* read)(struct file *, void * buf, size_t len, loff_t * ofsp);
    int		 (* fsync)(struct file *, int datasync);
    loff_t	 (* llseek)(struct file *, loff_t, int);
};

/*** Files on disk, or real block devices ***/

extern void file_inode_destructor(struct inode *);

static inline struct file *
filp_open_real(const char * name, int flags, umode_t mode)
{
    int fd = open(name, flags, mode);
    if (unlikely(fd < 0)) {
	return ERR_PTR(-errno);
    }

    assert((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR);

    struct stat statbuf;
    error_t const err = UMC_kernelize(fstat(fd, &statbuf));
    if (unlikely(err)) {
	close(fd);
	return ERR_PTR(err);
    }

    /* This appears to be the way to get the size of a block device or a file */
    off_t lseek_end_ofs = lseek(fd, 0, SEEK_END); /* (go back) */ lseek(fd, 0, SEEK_SET);

    assert_imply(S_ISREG(statbuf.st_mode), statbuf.st_size == lseek_end_ofs);

#if 0	    // S_BLOCKIO_TYPE
#define S_BLOCKIO_TYPE	S_IFBLK	    /* make block devices look like block devices */
#else
#define S_BLOCKIO_TYPE	S_IFREG	    /* make block devices look like files */
#endif

    /* Hack /dev/zero to look like a big block device (or file) */
    if (S_ISCHR(statbuf.st_mode)) {
	struct stat zero_statbuf;
	int rc = stat("/dev/zero", &zero_statbuf);
	if (rc == 0 && statbuf.st_rdev == zero_statbuf.st_rdev) {
	    statbuf.st_size = 1ul << 40;
	    statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
	}
    } else if (S_ISBLK(statbuf.st_mode)) {
	statbuf.st_size = lseek_end_ofs;
	statbuf.st_mode = S_BLOCKIO_TYPE | (statbuf.st_mode & 0777);
    }

    trace_file("OPEN FILE name='%s' fd=%d statbuf.st_size=%"PRIu64
	       " lseek_end_ofs=%"PRId64"/0x%"PRIx64,
               name, fd, statbuf.st_size, lseek_end_ofs, lseek_end_ofs);

    struct file * file = record_alloc(file);
    file->inode = record_alloc(file->inode);
    init_inode(file->inode, I_TYPE_FILE, (umode_t)statbuf.st_mode, statbuf.st_size, flags, fd);
    file->inode->UMC_destructor = file_inode_destructor;
    return file;
}

static inline void
filp_close_real(struct file * file)
{
    assert_eq(file->inode->UMC_type, I_TYPE_FILE);
    iput(file->inode);
    record_free(file);
}

/* From /usr/include sys/uio.h */
struct iovec;
extern ssize_t readv (int __fd, const struct iovec *, int __count);
extern ssize_t writev (int __fd, const struct iovec *, int __count);
extern ssize_t preadv (int __fd, const struct iovec *, int __count, __off_t);
extern ssize_t pwritev (int __fd, const struct iovec *, int __count, __off_t);

#define vfs_read(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(pread((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) \
		    *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_write(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(pwrite((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) \
		    *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_readv(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc = UMC_kernelize64(preadv((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		if (likely(_rc > 0)) \
		    *(seekposp) += _rc; \
		_rc; \
	    })

#define vfs_writev(file, iovec, nvec, seekposp) \
	    ({ \
		ssize_t _rc; \
		if ((file)->inode->UMC_type == I_TYPE_SOCK) { \
		    _rc = UMC_kernelize64(writev((file)->inode->UMC_fd, (iovec), (nvec))); \
		} else { \
		    verify_eq((file)->inode->UMC_type, I_TYPE_FILE); \
		    _rc = UMC_kernelize64(pwritev((file)->inode->UMC_fd, (iovec), (nvec), *(seekposp))); \
		    if (likely(_rc > 0)) \
			*(seekposp) += _rc; \
		} \
		_rc; \
	    })

/* Note anachronism:  this simulates the vfs_fsync definition from LINUX_VERSION 2.6.35 */
#define vfs_fsync(file, datasync) \
	    UMC_kernelize((datasync) ? fdatasync((file)->inode->UMC_fd) \
				     : fsync((file)->inode->UMC_fd))

static inline error_t
sync_page_range(struct inode * inode, void * mapping, loff_t offset, loff_t nbytes)
{
    error_t err =  UMC_kernelize(sync_file_range(inode->UMC_fd, offset, nbytes,
	    0/* SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER) */));

    if (err == -ESPIPE) 
	err = 0;	/* /dev/zero acting as a block device */
    return err;
}

/* Get a handle for a UMC internal (fake) layered block device */
static inline struct file *
filp_open_bdev(const char * pathname, int inflags)
{
    int flags = inflags & O_ACCMODE;
    fmode_t fmode = FMODE_READ | (flags != O_RDONLY ? FMODE_WRITE : 0);
    if (!!(inflags & O_EXCL))
	fmode |= FMODE_EXCL;

    struct block_device * bdev = _open_bdev(pathname, fmode);
    if (IS_ERR(bdev)) {
	pr_warning("cannot open pathname='%s', err=%ld\n", pathname, PTR_ERR(bdev));
	return ERR_PTR(PTR_ERR(bdev));
    }

    struct file * file = record_alloc(file);
    file->inode = bdev->bd_inode;
    file->f_openmode = fmode;
    return file;
}

static inline void
filp_close_bdev(struct file * file)
{
    assert_eq(file->inode->UMC_type, I_TYPE_BDEV);
    _close_bdev(BDEV_I(file->inode), file->f_openmode);
    record_free(file);
}

static inline struct file *
filp_open(const char * path, int flags, umode_t mode)
{
    /* XXX Hack to detect internal block device names not in the real filesystem */
    static char prefix[64];
    if (!*prefix)
	snprintf(prefix, sizeof(prefix), "%s/dev/", UMC_fuse_mount_point);

    if (!strncmp(path, prefix, strlen(prefix))) {
	/* path is intended as a UMC internal name */
	return filp_open_bdev(path, flags);
    } else {
	/* path is intended as a real name in the real filesystem */
	return filp_open_real(path, flags, mode);
    }
}

static inline void
filp_close(struct file * file, void * unused)
{
    if (file->inode->UMC_type == I_TYPE_BDEV)
	filp_close_bdev(file);
    else
	filp_close_real(file);
}

/*** unused by UMC ***/

/* unused */
struct dentry {
    struct inode	      * d_inode;
};

#define d_unhashed(dentry)		true	//XXXX ?

struct nameidata;

typedef struct {
    int				count;
} read_descriptor_t;

struct file_ra_state { };

#endif /* UMC_FILE_H */
