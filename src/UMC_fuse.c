/* UMC_fuse.c
 * Usermode emulation for kernel-code /proc services running in usemode, using FUSE
 * Copyright 2016-2019 David A. Butterfield
 *
 * proc_create_data() and remove_proc_entry() are used by the program to build a tree of
 * /proc directory entries representing the filesystem structure.
 *
 * UMC_fuse_getattr, UMC_fuse_readdir, UMC_fuse_open, UMC_fuse_read, and UMC_fuse_write
 * are called by FUSE when an external application accesses or writes one of our nodes.
 *
 * UMC_fuse_start, UMC_fuse_stop, and UMC_fuse_exit initialize and/or free resources.
 *
 * XXX Still called pde here, the nodes are somewhat more general than that.
 */
#define NAME UMC_FUSE
#include "usermode_lib.h"

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64	/* fuse seems to want this even on 64-bit */
#include <fuse.h>
#define FLAG_NOPATH 0

#define trace_fs(fmtargs...)	// trace(fmtargs)	/* calls from fuse */
#define trace_app(fmtargs...)	// trace(fmtargs)	/* calls from app */
#define trace_cb(fmtargs...)	// trace(fmtargs)	/* calls to app callbacks */
#define trace_dev_cb(fa...)	// trace(fa)		/* calls to bdev callbacks */

#define foreach_child_node(parent, node) \
    for ((node) = (parent)->child; node; node = node->sibling)

const char * UMC_fuse_mount_point;

//XXX limitation: single instance
static volatile sys_thread_t UMC_FUSE_THREAD;	/* thread runs fuse loop */
static DEFINE_MUTEX(UMC_fuse_lock);		//XXXX nasty big lock could be fixed
static struct proc_dir_entry * UMC_PDE_ROOT;    /* /UMCfuse		*/
static struct proc_dir_entry * UMC_PDE_PROC;	/* /UMCfuse/proc	*/
static struct proc_dir_entry * UMC_PDE_DEV;	/* /UMCfuse/dev		*/
static struct proc_dir_entry * UMC_PDE_SYS;	/* /UMCfuse/sys		*/
static struct proc_dir_entry * UMC_PDE_MOD;	/* /UMCfuse/sys/module	*/

static string_t UMCfuse_tree_fmt(void);	/* dump pde tree for debugging */

/*** These functions maintain the node tree ***/

/* node self-consistency check */
static inline void
UMCfuse_node_check(struct proc_dir_entry const * pde)
{
    assert(S_ISREG(pde->inode->i_mode) || S_ISDIR(pde->inode->i_mode) || S_ISBLK(pde->inode->i_mode),
	   "pde[%s]->mode=0x%x", pde->name, pde->inode->i_mode);
    assert(!strchr(pde->name, '/'), "'%s'", pde->name);
    assert_eq(!!pde->parent, pde != UMC_PDE_ROOT);
    assert_eq(pde->namelen, strlen(pde->name));
    assert(pde->inode);
    assert_imply(!!pde->child, S_ISDIR(pde->inode->i_mode));
    assert_imply(pde == UMC_PDE_ROOT, !pde->sibling);
}

/* Return the number of direct child nodes of pde */
static inline unsigned int
UMCfuse_node_nchild(struct proc_dir_entry const * pde)
{
    UMCfuse_node_check(pde);
    bool isdir = S_ISDIR(pde->inode->i_mode);
    uint32_t ret = 0;
    foreach_child_node(pde, pde) {
	UMCfuse_node_check(pde);
	++ret;
    }
    assert_imply(!isdir, ret == 0);
    return ret;
}

/* Create a new node that can be added to the tree */
static struct proc_dir_entry *
_UMCfuse_node_create(char const * name, umode_t mode, 
		   struct file_operations const * fops, void * data, struct inode * inode)
{
    uint32_t namelen = strlen(name);
    assert(name);
    assert(*name);
    assert(!strchr(name, '/'), "'%s'", name);

    /* extra space for the name string -- the terminating NUL is already counted */
    struct proc_dir_entry * pde = vzalloc(sizeof(*pde) + namelen);

    if (!inode) {
	if (!(mode & S_IFMT))
	    mode |= S_IFREG;
	inode = record_alloc(inode);
	init_inode(inode, I_TYPE_PROC, mode, 0, 0, -1);
    }

    inode->UMC_node = pde;

    memcpy(pde->name, name, namelen);
    pde->namelen = namelen;
    pde->inode = inode;
    pde->proc_fops = fops;
    pde->data = data;

    return pde;
}

/* Free a node after it has been removed from the tree */
static error_t
_UMCfuse_node_destroy(struct proc_dir_entry * pde)
{
    if (pde->child) {
	sys_warning("fuse node %s still has child\n%s", pde->name, UMCfuse_tree_fmt());
	return -EBUSY;
    }

    //XXXXX should do this via iput
    if (pde->inode->UMC_type == I_TYPE_PROC)
	record_free(pde->inode);
    else
	pde->inode->UMC_node = NULL;

    vfree(pde);
    return E_OK;
}

/* Create and add the named node as a direct child of the parent pde */
static struct proc_dir_entry *
UMCfuse_node_add(char const * name, umode_t mode, struct proc_dir_entry * parent,
		   struct file_operations const * fops, void * data, struct inode * inode)
{
    assert(parent);
    assert(S_ISDIR(parent->inode->i_mode));

    struct proc_dir_entry * pde = _UMCfuse_node_create(name, mode, fops, data, inode);
    pde->parent = parent;
    pde->sibling = pde->parent->child;
    pde->parent->child = pde;

    trace_verbose("created /proc %s node %s under %s",
		    S_ISDIR(mode)?"DIRECTORY":"", name, parent->name);
    UMCfuse_node_check(pde);
    return pde;
}

/* Remove the named item as a direct child of the parent pde and free it */
static error_t
UMCfuse_node_remove(char const * name, struct proc_dir_entry * parent)
{
    trace_verbose("%s", name);
    assert(S_ISDIR(parent->inode->i_mode));

    struct proc_dir_entry * * pdep;
    for (pdep = &parent->child; *pdep; pdep = &(*pdep)->sibling) {
	UMCfuse_node_check(*pdep);
	if (strcmp(name, (*pdep)->name))
	    continue;	    /* name mismatch, try next sibling */

	if ((*pdep)->child)
	    return -ENOTEMPTY;

	struct proc_dir_entry * pde_to_free = *pdep;
	*pdep = (*pdep)->sibling;	/* remove from list */
	return _UMCfuse_node_destroy(pde_to_free);
    }

    return -ENOENT;
}

/******************************************************************************/
/*** These functions operate on one particular node in the tree ***/

/* Pass back the attributes of the specified node */
static error_t
UMCfuse_node_getattr(struct proc_dir_entry * pde, struct stat * st)
{
    struct inode * inode = pde_inode(pde);

    st->st_mode = pde->inode->i_mode;

    /* Trouble is that if we make the node appear as a block device to the application,
     * fuse additionally assumes that to mean to let the kernel interpret the dev_t as
     * referring to a kernel major/minor, instead of presenting system calls to our
     * handlers as for other st_mode values.
     */
    if (S_ISBLK(pde->inode->i_mode))
	st->st_mode = S_IFREG | (pde->inode->i_mode & 0777);

    st->st_nlink = 1u + UMCfuse_node_nchild(pde);   /* assume no . or .. */
    st->st_uid = 0;
    st->st_size = inode->i_size;
    st->st_atime = inode->i_atime;
    st->st_mtime = inode->i_mtime;
    st->st_ctime = inode->i_ctime;
    st->st_rdev = inode->i_rdev;
    // st->st_blocks		    // blocks allocated

    /* Hack: allow users in program's group the same write access as owner */
    /* If the program's gid is zero, allow access to the adm group */
    st->st_gid = getegid();
    if (!st->st_gid)
	st->st_gid = 4;	/* adm */   //XXX
    if (st->st_mode & 0200)
	st->st_mode |= 0020;

    return E_OK;
}

/* Pass back a list of children of a directory node, starting at child index ofs */
static error_t
UMCfuse_node_readdir(struct proc_dir_entry * pde, void * buf, fuse_fill_dir_t filler, off_t ofs)
{
    pde_inode(pde)->i_atime = time(NULL);
    uint32_t next_idx = ofs;
    foreach_child_node(pde, pde) {
	UMCfuse_node_check(pde);
	if (ofs) {
	    --ofs;
	    continue;	/* skip over the first (ofs) items without processing */
	}
	trace_verbose("    %s child=%s", path, pde->name);
	if (filler(buf, pde->name, NULL, ++next_idx))
	    break;	/* buffer full */
    }

    return E_OK;
}

/* We store a pointer to struct file in fuse_file_info->fh for open nodes */
#define FFI_FILE(ffi)	((struct file *)(ffi)->fh)  /* fuse_file_info --> file */
#define FFI_INODE(ffi)	file_inode(FFI_FILE(ffi))   /* fuse_file_info --> inode */
#define FFI_PDE(ffi)	inode_pde(FFI_INODE(ffi))   /* fuse_file_info --> pde */
#define FILE_PDE(file)	inode_pde(file_inode(file)) /* file --> pde */

/* Call the pde's open function */
static error_t
UMCfuse_node_open(struct fuse_file_info * fi)
{
    struct proc_dir_entry * pde = FFI_PDE(fi);
    assert(pde);
    if (!pde->proc_fops || !pde->proc_fops->open)
	return -EINVAL;

    struct file * file = FFI_FILE(fi);
    assert(file);

    //XXXXXX hold node

    mutex_unlock(&UMC_fuse_lock);
    trace_cb();
    error_t err = pde->proc_fops->open(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->open", pde->name);
    mutex_lock(&UMC_fuse_lock);

    return err;
}

/* Call the pde's release function */
static error_t
UMCfuse_node_release(struct fuse_file_info * fi)
{
    struct proc_dir_entry * pde = FFI_PDE(fi);
    assert(pde);
    if (!pde->proc_fops || !pde->proc_fops->release)
	return -EINVAL;

    struct file * file = FFI_FILE(fi);
    assert(file);

    mutex_unlock(&UMC_fuse_lock);
    trace_cb();
    error_t err = pde->proc_fops->release(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->release", pde->name);
    mutex_lock(&UMC_fuse_lock);

    //XXXXXX release node

    return err;
}

/* Read into buf up to size bytes starting at ofs in data returned by pde's read function */
static ssize_t
UMCfuse_node_read(struct fuse_file_info * fi, char * buf, size_t size, off_t * ofs)
{
    struct proc_dir_entry * pde = FFI_PDE(fi);
    assert(pde);
    if (!pde->proc_fops || !pde->proc_fops->read)
	return -EINVAL;

    struct file * file = FFI_FILE(fi);
    assert(file);

    mutex_unlock(&UMC_fuse_lock);
    trace_cb();
    ssize_t bytes_read = pde->proc_fops->read(file, buf, size, ofs);
    expect_rc(bytes_read, fops->read, "pde[%s]->proc_fops->read", pde->name);
    mutex_lock(&UMC_fuse_lock);

    return bytes_read;
}

/* Write from buf up to size bytes starting at ofs into pde */
static ssize_t
UMCfuse_node_write(struct fuse_file_info * fi, char const * buf, size_t size, off_t * ofs)
{
    struct proc_dir_entry * pde = FFI_PDE(fi);
    assert(pde);
    if (!pde->proc_fops || !pde->proc_fops->write)
	return -EINVAL;

    struct file * file = FFI_FILE(fi);
    assert(file);

    mutex_unlock(&UMC_fuse_lock);
    trace_cb();
    ssize_t bytes_written = pde->proc_fops->write(file, buf, size, ofs);
    // expect_eq(bytes_written, size, "pde[%s]->proc_fops->write", pde->name);
    mutex_lock(&UMC_fuse_lock);

    return bytes_written;
}

static error_t
UMCfuse_node_fsync(struct fuse_file_info * fi, int datasync)
{
    struct proc_dir_entry * pde = FFI_PDE(fi);
    assert(pde);
    if (!pde->proc_fops || !pde->proc_fops->fsync)
	return 0;

    struct file * file = FFI_FILE(fi);
    assert(file);

    mutex_unlock(&UMC_fuse_lock);
    trace_cb();
    error_t err = pde->proc_fops->fsync(file, datasync);
    mutex_lock(&UMC_fuse_lock);
    return err;
}

/******************************************************************************/
/* These operate on a subtree starting at pde_root, with path names relative thereto
 * (pde_root can be any position in the tree, even a leaf)
 */

/* Format a subtree into a debugging string representation */
static string_t
_UMCfuse_tree_fmt(struct proc_dir_entry * pde_root, uint32_t level)
{
    struct proc_dir_entry * pde = pde_root;
    string_t ret = kasprintf(IGNORED,
		    "%*snode@%p={name='%s' mode=0%o%s rdev=%d/%d fd=%d}\n", level*4, "",
		    pde, pde->name, pde->inode->i_mode,
			S_ISDIR(pde->inode->i_mode) ? " (DIR)" :
			S_ISBLK(pde->inode->i_mode) ? " (BLK)" :
			S_ISREG(pde->inode->i_mode) ? " (REG)" : "",
		    MAJOR(pde->inode->i_rdev), MINOR(pde->inode->i_rdev), pde->inode->UMC_fd);

    foreach_child_node(pde, pde)
	ret = string_concat_free(ret, _UMCfuse_tree_fmt(pde, level + 1));

    return ret;
}

static string_t
UMCfuse_tree_fmt(void)
{
    struct proc_dir_entry * pde_root = UMC_PDE_ROOT;
    if (!pde_root)
	return sys_mem_zalloc(1);	/* empty string */
    return _UMCfuse_tree_fmt(pde_root, 1);
}

/* Callable under gdb to dump out the fuse tree */
static void __attribute__((__unused__))
UMCfuse_tree_dump(void)
{
    string_t str = UMCfuse_tree_fmt();
    sys_sprintf("%s", str);
    vfree(str);
}

/* Try to find a pde matching path name, starting at the given pde_root node --
 * Returns NULL if no matching node is found.
 */
static struct proc_dir_entry *
UMCfuse_lookup(struct proc_dir_entry * pde_root, sstring_t path)
{
    struct proc_dir_entry * pde;
    trace_verbose("%s", path);
    UMCfuse_node_check(pde_root);
    assert(S_ISDIR(pde_root->inode->i_mode));

    while (*path == '/')
	path++;
    if (*path == '\0') {
	return pde_root;    /* path string ended at this node */
    }

    uint32_t name_ofs;	    /* offset into pde's name string */
    foreach_child_node(pde_root, pde) {
	UMCfuse_node_check(pde);
	for (name_ofs = 0 ; path[name_ofs] == pde->name[name_ofs]; name_ofs++)
	    if (pde->name[name_ofs] == '\0')
		break;	/* end of matching strings */

	if (pde->name[name_ofs] != '\0')
	    continue;	/* mismatch -- try the next sibling */

	if (path[name_ofs] != '\0' && path[name_ofs] != '/')
	    continue;					/* mismatch -- node name was shorter */

	/* Found an entry matching this path segment */
	if (path[name_ofs] == '\0')
	    return pde;		    /* this was the last path segment */

	/* Descend (recursion) to lookup the next path segment with pde as root */
	return UMCfuse_lookup(pde, path + name_ofs);
    }

    WARN_ONCE(true, "UMCfuse_lookup failed to find %s under %s", path, pde_root->name);
    return NULL;
}

/******************************************************************************/
/* These are called by FUSE to implement the filesystem functions */

static error_t
UMC_fuse_getattr(sstring_t path, struct stat * st)
{
    error_t err = -ENOENT;
    trace_fs("%s", path);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = UMCfuse_lookup(UMC_PDE_ROOT, path);
    if (pde)
	err = UMCfuse_node_getattr(pde, st);

    mutex_unlock(&UMC_fuse_lock);
    return err;
}

static error_t
UMC_fuse_readdir(char const * path, void * buf,
		 fuse_fill_dir_t filler, off_t ofs, struct fuse_file_info * fi)
{
    error_t err = -ENOENT;
    trace_fs("%s ofs=%"PRIu64, path, ofs);
    assert_eq(FFI_FILE(fi), NULL);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = UMCfuse_lookup(UMC_PDE_ROOT, path);
    if (pde) {
	if (!S_ISDIR(pde->inode->i_mode))
	    err = -ENOTDIR;
	else
	    err = UMCfuse_node_readdir(pde, buf, filler, ofs);
    }

    mutex_unlock(&UMC_fuse_lock);
    return err;
}

static error_t
UMC_fuse_open(char const * path, struct fuse_file_info * fi)
{
    error_t err = -ENOENT;
    trace_fs("%s", path);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = UMCfuse_lookup(UMC_PDE_ROOT, path);
    if (pde) {
	if (S_ISDIR(pde->inode->i_mode))
	    err = -EISDIR;
	else {
	    struct file * file = record_alloc(file);
	    file->inode = pde_inode(pde);
	    fi->fh = (uintptr_t)file;	/* stash file pointer for lower-level functions */
	    err = UMCfuse_node_open(fi);
	    if (err) {
		fi->fh = (uintptr_t)NULL;
		record_free(file);
	    }
	}
    }

    mutex_unlock(&UMC_fuse_lock);

    if (!err && !S_ISBLK(pde->inode->i_mode)) {
	fi->nonseekable = true;
	fi->direct_io = true;	    /* "-o direct_io" but per-file */
    }

    return err;
}

static error_t
UMC_fuse_release(char const * path, struct fuse_file_info * fi)
{
    error_t err = -EINVAL;
    trace_fs("%s", path);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = FFI_PDE(fi);
    if (!FLAG_NOPATH) assert_eq(pde,
	    (long)({struct proc_dir_entry * foo = UMCfuse_lookup(UMC_PDE_ROOT, path); foo;}));

    if (pde) {
	if (!S_ISDIR(pde->inode->i_mode))
	    err = UMCfuse_node_release(fi);
    }

    mutex_unlock(&UMC_fuse_lock);

    if (!err) {
	record_free(FFI_FILE(fi));
	fi->fh = (uintptr_t)NULL;
    }

    return err;
}

static int /*ssize_t?*/
UMC_fuse_read(char const * path, char * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    ssize_t ret = -EINVAL;
    buf[0] = '\0';
    trace_fs("%s ofs=%"PRIu64, path, ofs);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = FFI_PDE(fi);
    if (!FLAG_NOPATH) assert_eq(pde,
	    (long)({struct proc_dir_entry * foo = UMCfuse_lookup(UMC_PDE_ROOT, path); foo;}));

    if (pde) {
	if (!S_ISDIR(pde->inode->i_mode))
	    ret = UMCfuse_node_read(fi, buf, size, &ofs);

	if (ret >= 0)
	    pde_inode(pde)->i_atime = time(NULL);
    }

    mutex_unlock(&UMC_fuse_lock);

    trace_fs("READ %s REPLY len=%"PRIu64" '%.*s'", path, ret, (uint32_t)ret, buf);
    return ret;
}

static int /*ssize_t?*/
UMC_fuse_write(char const * path, char const * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    ssize_t ret = -EINVAL;
    trace_fs("WRITE %s '%.*s'", path, (int)size, buf);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = FFI_PDE(fi);
    if (!FLAG_NOPATH) assert_eq(pde,
	    (long)({struct proc_dir_entry * foo = UMCfuse_lookup(UMC_PDE_ROOT, path); foo;}));

    if (pde) {
	if (!S_ISDIR(pde->inode->i_mode))
	    ret = UMCfuse_node_write(fi, buf, size, &ofs);

	if (ret >= 0)
	    pde_inode(pde)->i_mtime = time(NULL);
    }

    mutex_unlock(&UMC_fuse_lock);

    trace_fs("WRITE %s REPLY len=%"PRIu64" '%.*s'", path, ret, (uint32_t)ret, buf);
    return ret;
}

static error_t
UMC_fuse_fsync(char const * path, int datasync, struct fuse_file_info * fi)
{
    error_t err = -EINVAL;
    trace_fs("FSYNC %s %d", path, datasync);

    mutex_lock(&UMC_fuse_lock);

    struct proc_dir_entry * pde = FFI_PDE(fi);
    if (!FLAG_NOPATH) assert_eq(pde,
	    (long)({struct proc_dir_entry * foo = UMCfuse_lookup(UMC_PDE_ROOT, path); foo;}));

    if (pde) {
	if (!S_ISDIR(pde->inode->i_mode))
	    err = UMCfuse_node_fsync(fi, datasync);
    }

    mutex_unlock(&UMC_fuse_lock);

    trace_fs("FSYNC %s REPLY ret=%d", path, err);
    return err;
}

/******************************************************************************/
/* These are called by the application program to build and
 * operate on a PDE tree rooted at the global single-instance PDE_ROOT.
 */

/* Add an entry to the tree directly under parent -- attaches to UMC_PDE_PROC if parent is NULL */
struct proc_dir_entry *
UMC_pde_create(char const * name, umode_t mode, struct proc_dir_entry * parent,
				    struct file_operations const * fops, void * data)
{
    if (!parent)
	parent = UMC_PDE_PROC;

    trace_app("%s/%s", parent->name, name);

    mutex_lock(&UMC_fuse_lock);
    struct proc_dir_entry * ret = UMCfuse_node_add(name, mode, parent, fops, data, NULL);
    mutex_unlock(&UMC_fuse_lock);

    return ret;
}

/* Remove an entry from directly under parent */
error_t
UMC_pde_remove(char const * name, struct proc_dir_entry * parent)
{
    if (!parent)
	parent = UMC_PDE_PROC;

    trace_app("%s/%s", parent->name, name);

    mutex_lock(&UMC_fuse_lock);
    error_t ret = UMCfuse_node_remove(name, parent);
    mutex_unlock(&UMC_fuse_lock);
    return ret;
}

/*** These are for reading and writing "module_param_named" global variables ***/
/* They appear under /sys/module/THIS_MODULE->name/parameters */
//XXXX You can write the variables, but nothing will happen unless someone then looks at them...

static ssize_t
module_param_write(struct file * file, char const * buf, size_t writesize, loff_t * ofs)
{
    trace_cb("writesize=%lu, ofs=%lu", writesize, *ofs);
    if (writesize == 0) {
	return -EINVAL;
    }
    assert(buf);
    assert_eq(*ofs, 0);

    errno = 0;
    long long data = strtoll(buf, NULL, 0);
    if (errno != 0) {
	return -EINVAL;
    }

    struct proc_dir_entry * pde = inode_pde(file->inode);
    UMCfuse_node_check(pde);

    //XXXX endian
    size_t size = min(sizeof(data), pde->inode->i_size);
    memcpy(pde->data, &data, size);
    
    return (ssize_t)writesize;
}

static ssize_t
module_param_read(struct file * file, void * buf, size_t readsize, loff_t * ofs)
{
    trace_cb("readsize=%lu, ofs=%lu", readsize, *ofs);
    if (readsize == 0) {
	return -EINVAL;
    }
    assert(buf);
    if (*ofs != 0)
	return 0;	    //XXX good enough?

    struct proc_dir_entry * pde = inode_pde(file->inode);
    UMCfuse_node_check(pde);

    //XXXX endian
    long long data = 0;
    size_t size = min(sizeof(data), pde->inode->i_size);
    memcpy(&data, pde->data, size);
    
    int nchar = snprintf(buf, readsize, "%lld\n", data);
    if ((size_t)nchar > readsize)
	nchar = readsize;

    return nchar;
}

static error_t
module_param_open(struct inode * inode, struct file * file)
{
    trace_cb();
    return E_OK;
}

static error_t
module_param_release(struct inode * inode, struct file * file)
{
    trace_cb();
    return E_OK;
}

static struct file_operations module_fops = {
    .open = module_param_open,
    .release = module_param_release,
    .read = module_param_read,
    .write = module_param_write,
};

/* Create an entry in /sys/module/THIS_MODULE->name/parameters */
struct proc_dir_entry *
UMC_module_param_create(char const * name, void * varp, size_t size,
			umode_t mode, struct module * owner)
{
    assert(size == 1 || size == 2 || size == 4 || size == 8, "%ld", size);

    /* e.g. /UMCroot/sys/module/scsi_tgt/parameters/xxx */
    struct proc_dir_entry * parent = UMC_PDE_MOD;
    assert(parent);
    parent = UMCfuse_lookup(parent, owner->name);
    if (!parent)
	return NULL;
    parent = UMCfuse_lookup(parent, "parameters");
    if (!parent)
	return NULL;

    struct proc_dir_entry * ret = UMC_pde_create(name, mode, parent, &module_fops, varp);
    ret->inode->i_size = size;
    return ret;
}

error_t
UMC_module_param_remove(char const * name, struct module * owner)
{
    struct proc_dir_entry * parent = UMC_PDE_MOD;
    assert(parent);
    parent = UMCfuse_lookup(parent, owner->name);
    if (!parent)
	return -ENOENT;
    parent = UMCfuse_lookup(parent, "parameters");
    if (!parent)
	return -ENOENT;

    return UMC_pde_remove(name, parent);
}

/* Create the /sys/module/THIS_MODULE->name/parameters directory for a module */
struct proc_dir_entry *
UMC_fuse_module_mkdir(char * modname)
{
    trace_app("%s", modname);
    struct proc_dir_entry * pde_parent = UMC_PDE_ROOT;
    pde_parent = UMCfuse_lookup(pde_parent, "sys");
    assert(pde_parent);
    pde_parent = UMCfuse_lookup(pde_parent, "module");
    assert(pde_parent);
    pde_parent = UMC_pde_create(modname, PROC_DIR_UMODE, pde_parent, NULL, NULL);
    assert(pde_parent);
    return UMC_pde_create("parameters", PROC_DIR_UMODE, pde_parent, NULL, NULL);
}

error_t
UMC_fuse_module_rmdir(char * modname)
{
    trace_app("%s", modname);
    struct proc_dir_entry * pde_mymodule;
    struct proc_dir_entry * pde_parent = UMC_PDE_ROOT;
    pde_parent = UMCfuse_lookup(pde_parent, "sys");
    assert(pde_parent);
    pde_parent = UMCfuse_lookup(pde_parent, "module");
    assert(pde_parent);
    pde_mymodule = UMCfuse_lookup(pde_parent, modname);
    if (!pde_mymodule)
	return -ENOENT;
    UMC_pde_remove("parameters", pde_mymodule);
    UMC_pde_remove(modname, pde_parent);
    return E_OK;
}

/*** Entries for /dev ***/

static error_t
UMC_fuse_dev_open(struct inode * inode, struct file * file)
{
    trace_dev_cb("=========== OPEN(%s)", FILE_PDE(file)->name);
    return inode->i_bdev->bd_disk->fops->open(inode->i_bdev, inode->i_mode);
}

static error_t
UMC_fuse_dev_release(struct inode * inode, struct file * file)
{
    trace_dev_cb("=========== RELEASE(%s)", FILE_PDE(file)->name);
    inode->i_bdev->bd_disk->fops->release(inode->i_bdev->bd_disk, inode->i_mode);
    return E_OK;
}

static void
UMC_fuse_endio(struct bio * bio, error_t err)
{
    trace_dev_cb("=========== ENDIO()");
    bio->bi_error = err;
    complete((struct completion *)bio->bi_private);
}

static ssize_t
UMC_fuse_dev_io(struct file * file, void * buf, size_t iosize, loff_t * ofs, int rw)
{
    struct bio * bio;
    void * p = buf;
    size_t size = iosize;
    int npage = 2 + size / PAGE_SIZE;
    struct page pages[npage];
    struct page * page = &pages[0];
    memset(pages, 0, sizeof(pages));

    assert(buf);
    expect_eq(*ofs % 512, 0, "EINVAL unaligned file offset to bdev %s", FILE_PDE(file)->name);
    expect_eq(iosize % 512, 0, "EINVAL unaligned iosize to bdev %s", FILE_PDE(file)->name);
    if (*ofs % 512)
	return -EINVAL;
    if (iosize % 512)
	return -EINVAL;

    bio = bio_alloc(0, npage);
    bio_set_dev(bio, file->inode->i_bdev);
    bio->bi_sector = *ofs / 512;
    bio->bi_end_io = UMC_fuse_endio;
    // bio->bi_rw = FUA ?
    // bio->bi_flags |= 0;

    /* Compute start offset in first page */
    loff_t page_off = offset_in_page(p);
    assert_lt(page_off, PAGE_SIZE);

    while (size) {
	assert(page < pages + npage);
	size_t page_datalen = min(PAGE_SIZE - page_off, size);
	page->vaddr = (void *)((long)p & PAGE_MASK);
	page->order = 1;
	bio_add_page(bio, page, page_datalen, page_off);
	p += page_datalen;
	size -= page_datalen;
	page++;
	page_off = 0;	/* non-first pages start at offset zero */
    }

    DECLARE_COMPLETION_ONSTACK(c);
    bio->bi_private = (void *)&c;

    ssize_t ret = submit_bio(rw, bio);
    if (!ret) {
	trace_dev_cb("=========== AWAITING ENDIO()");
	wait_for_completion(&c);
	trace_dev_cb("=========== PASSED ENDIO()");
	ret = bio->bi_error;
    }

    if (ret == E_OK)
	ret = iosize - bio->bi_size;

    bio_put(bio);

    return ret;
}

static ssize_t
UMC_fuse_dev_read(struct file * file, void * buf, size_t iosize, loff_t * ofs)
{
    trace_dev_cb("=========== READ(%s) %ld @%ld", FILE_PDE(file)->name, iosize, *ofs);
    ssize_t ret = UMC_fuse_dev_io(file, buf, iosize, ofs, READ);
    if (ret < 0)
	sys_warning("READ FAILED: (%s) %ld @%ld", FILE_PDE(file)->name, iosize, *ofs);
    return ret;
}

static ssize_t
UMC_fuse_dev_write(struct file * file, char const * buf, size_t iosize, loff_t * ofs)
{
    trace_dev_cb("=========== WRITE(%s) %ld @%ld", FILE_PDE(file)->name, iosize, *ofs);
    ssize_t ret = UMC_fuse_dev_io(file, _unconstify(buf), iosize, ofs, WRITE);
    if (ret < 0)
	sys_warning("WRITE FAILED: (%s) %ld @%ld", FILE_PDE(file)->name, iosize, *ofs);
    return ret;
}

static error_t
UMC_fuse_dev_fsync(struct file * file, int datasync)
{
    trace_dev_cb("=========== FSYNC(%s)", FILE_PDE(file)->name);
    struct proc_dir_entry * pde = inode_pde(file->inode);
    UMCfuse_node_check(pde);
    //XXXXX UMC_fuse_dev_fsync() unimplemented
    return E_OK;
}

static struct file_operations UMC_fuse_dev_fops = {
    .open = UMC_fuse_dev_open,
    .release = UMC_fuse_dev_release,
    .read = UMC_fuse_dev_read,
    .write = UMC_fuse_dev_write,
    .fsync = UMC_fuse_dev_fsync,
};

struct proc_dir_entry *
UMC_fuse_bdev_add(const char * name, struct inode * inode)
{
    trace_app("%s %d/%d 0%3o", name, MAJOR(inode->i_rdev), MINOR(inode->i_rdev), inode->i_mode);
    struct proc_dir_entry * pde;
    assert(S_ISBLK(inode->i_mode));
    assert(inode->i_bdev);

    mutex_lock(&UMC_fuse_lock);
    pde = UMCfuse_node_add(name, inode->i_mode, UMC_PDE_DEV,
			    &UMC_fuse_dev_fops, NULL, inode);
    mutex_unlock(&UMC_fuse_lock);
    return pde;
}

error_t
UMC_fuse_bdev_remove(const char * name)
{
    trace_app("%s", name);
    mutex_lock(&UMC_fuse_lock);
    error_t err = UMCfuse_node_remove(name, UMC_PDE_DEV);
    mutex_unlock(&UMC_fuse_lock);
    return err;
}

/******************************************************************************/
/** fuse thread control ***/

// fuse_file_info
//	int flags;		    /* Open flags.  Available in open() and release() */
//	int writepage;		    /* In case of a write operation indicates if this was caused by a writepage */
//	unsigned int flush:1;	    /* Indicates a flush operation.  Set in flush operation */
//	unsigned int direct_io:1;   /* Can be filled in by open, to use direct I/O on this file. */
//	unsigned int nonseekable:1; /* Can be filled in by open, to indicate that the file is not seekable. */

static struct fuse_operations const pde_ops = {
    .getattr	= UMC_fuse_getattr,
    .open	= UMC_fuse_open,
    .release	= UMC_fuse_release,
    .read	= UMC_fuse_read,
    .write	= UMC_fuse_write,
    .fsync	= UMC_fuse_fsync,
    .readdir	= UMC_fuse_readdir,
    .flag_nopath = FLAG_NOPATH,
};

/* Example fuse filesystem /etc/mtab entry:
 *  fsname= mountpoint	subtype=pde options
 *  pde	    /UMCfuse	fuse.pde    rw,sync,nosuid,relatime,user_id=0,group_id=0,default_permissions,allow_other 0 0
    pde on /UMCfuse type fuse.pde  (rw,nosuid,relatime,sync,user_id=0,group_id=0,default_permissions,allow_other)

 */

/* Here starting up on the UMC_fuse thread */
static int
UMC_fuse_run(void * unused)
{
    assert_eq(unused, NULL);
    assert_eq(sys_thread_current(), UMC_FUSE_THREAD);

    /* XXXX setup UMC_fuse "current" -- change this to start a "kernel thread" */
    struct task_struct * task = UMC_current_alloc();
    UMC_current_init(task, sys_thread_current(), (void *)UMC_fuse_run,
			    unused, "UMC_fuse thread");
    UMC_current_set(task);

    char /*const*/ * UMC_fuse_argv[] = {
	"fuse_main",		    /* argv[0] */
	_unconstify(UMC_fuse_mount_point),
	//"--help",
	//"--version",
	//"-d",			    /* debug, implies -f */

	"-f",			    /* foreground (else daemonizes) */
	"-s",			    /* single-threaded */
	"-o", "subtype=pde",	    /* third field in /etc/mtab */
	"-o", "allow_other",	    /* any user can access our fuse tree */
	"-o", "auto_unmount",	    /* unmount fuse fs when program exits */

	// "-o", "auto_cache",	    /* invalidate kernel cache on each open (maybe?) */

	// "-o", "sync_read",	    /* perform all reads synchronously */
	// "-o", "sync",	    /* perform all I/O synchronously */
	// "-o", "max_readahead=0", /* max bytes to read-ahead */

	"-o", "atomic_o_trunc",	    /* avoid calls to truncate */
	"-o", "default_permissions",/* fuse do mode permission checking */
	// "-o", "dev",		    /* allow device nodes -- XXX interpreted as KERNEL dev_t! */

	NULL
    };

    int UMC_fuse_argc = ARRAY_SIZE(UMC_fuse_argv) - 1;

    sys_notice("UMC_fuse thread @%p starts up on tid=%u",
	       sys_thread_current(), sys_thread_num(sys_thread_current()));

    int ret = fuse_main(UMC_fuse_argc, UMC_fuse_argv, &pde_ops, NULL);

    if (ret == E_OK) {
	sys_notice("fuse_main returned %d -- FUSE thread exits", ret);
    } else {
	sys_warning("fuse_main returned %d -- FUSE thread exits", ret);
    }

    UMC_current_free(current);
    UMC_current_set(NULL);

    assert_eq(sys_thread_current(), UMC_FUSE_THREAD);
    UMC_FUSE_THREAD = NULL;
    sys_thread_exit(0);
}

/* Call once from any thread to initialize UMC_PDE_ROOT and start UMC_FUSE_THREAD */
error_t
UMC_fuse_start(const char * mountpoint)
{
    trace_init(true, false);
    assert(!UMC_FUSE_THREAD);
    assert(!UMC_PDE_ROOT);
    assert(mountpoint);

    UMC_fuse_mount_point = mountpoint;

    //XXXX should strrchr('/') this or treat root name special ?
    while (*mountpoint == '/')
	mountpoint++;		/* skip initial '/' sequence for the nodename */
    if (*mountpoint == '\0') {
	return -EINVAL;
    }
    UMC_PDE_ROOT = _UMCfuse_node_create(mountpoint, PROC_ROOT_UMODE, NULL, NULL, NULL);

    UMC_PDE_PROC = UMC_pde_create("proc", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_DEV = UMC_pde_create("dev", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_SYS = UMC_pde_create("sys", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_MOD = UMC_pde_create("module", PROC_DIR_UMODE, UMC_PDE_SYS, NULL, NULL);

    /* Create the mount point for the fuse filesystem */
    string_t cmd = kasprintf(IGNORED, "/bin/mkdir -p %s; chmod 777 %s",
			       UMC_fuse_mount_point, UMC_fuse_mount_point);
    int rc = system(cmd);
    expect_noerr(rc, "system(\"%s\")", cmd);
    kfree(cmd);

    sys_notice("created %s fuse root @%p -- starting fuse service",
		UMC_fuse_mount_point, UMC_PDE_ROOT);

    UMC_FUSE_THREAD = sys_thread_alloc(UMC_fuse_run, NULL, kstrdup("UMC_fuse", IGNORED));

    error_t err = sys_thread_start(UMC_FUSE_THREAD);
    expect_noerr(err, "sys_thread_start UMC_FUSE_THREAD");
    if (err != E_OK) {
	_UMCfuse_node_destroy(UMC_PDE_ROOT);
	UMC_PDE_ROOT = NULL;
    }

    return err;
}

error_t
UMC_fuse_exit(void)
{
    trace();
    assert(UMC_PDE_ROOT);

    if (UMC_FUSE_THREAD) {
	sys_warning("UMC_fuse_exit called while UMC_FUSE_THREAD still active");
	return -EBUSY;
    }

    UMC_pde_remove("module", UMC_PDE_SYS); UMC_PDE_MOD = NULL;
    UMC_pde_remove("sys", UMC_PDE_ROOT); UMC_PDE_SYS = NULL;
    UMC_pde_remove("dev", UMC_PDE_ROOT); UMC_PDE_DEV = NULL;
    UMC_pde_remove("proc", UMC_PDE_ROOT); UMC_PDE_PROC = NULL;

    _UMCfuse_node_destroy(UMC_PDE_ROOT); UMC_PDE_ROOT = NULL;

    return E_OK;
}

error_t
UMC_fuse_stop(void)
{
    /* If we prod the fuse thread it will return from fuse_main to UMC_fuse_run */
    sys_thread_t fusethread = UMC_FUSE_THREAD;
    if (!fusethread)
	return -EINVAL;

    trace("tkill %d, SIGTERM", fusethread->tid);
    int rc = tkill(fusethread->tid, SIGTERM);
    expect_eq(rc, 0, "tkill fuse tid=%u errno=%d '%s'",
		     fusethread->tid, errno, strerror(errno));

    /* Wait a second for fuse thread to return to UMC_fuse_run */
    int max = 1000;
    while (UMC_FUSE_THREAD) {
	if (!max--) {
	    sys_warning("UMC_fuse thread didn't exit timely");
	    return -EBUSY;
	}
	usleep(1000);
    }

    return E_OK;
}
