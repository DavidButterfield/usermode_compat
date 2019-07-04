/* UMC_fuse.c
 * Usermode emulation for kernel-code /proc consumers running in usemode, using FUSE
 * Copyright 2016-2019 David A. Butterfield
 *
 * proc_create_data() and remove_proc_entry() are used by the program to build a tree of
 * "/proc directory entries" representing the filesystem structure.
 *
 * UMC_fuse_getattr, UMC_fuse_readdir, UMC_fuse_open, UMC_fuse_read, and UMC_fuse_write
 * are called by FUSE when an external application accesses or writes one of our nodes.
 *
 * UMC_fuse_start, UMC_fuse_stop, and UMC_fuse_exit initialize and/or free resources.
 *
 * XXX Still called pde, the nodes are more general than that now.
 */
#define NAME UMC_FUSE
#include "usermode_lib.h"

// #define DOT_AND_DOT_DOT defined  //XXX not implemented

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64	/* fuse seems to want this even on 64-bit */
#include <fuse.h>

#define foreach_pde_child(parent, pde) \
    for ((pde) = (parent)->child; pde; pde = pde->sibling)


static volatile sys_thread_t UMC_FUSE_THREAD;	/* thread runs fuse loop */
static DEFINE_MUTEX(UMC_fuse_lock);		//XXX nasty big lock could be fixed
static const char * mount_point;

static struct proc_dir_entry * UMC_PDE_ROOT;    //XXX limitation: single instance
static struct proc_dir_entry * UMC_PDE_PROC;	/* /proc */
static struct proc_dir_entry * UMC_PDE_DEV;	/* /dev */
static struct proc_dir_entry * UMC_PDE_SYS;	/* /sys */
static struct proc_dir_entry * UMC_PDE_MOD;	/* /sys/module */

static string_t _UMCpde_tree_fmt(struct proc_dir_entry *, uint32_t level);
static string_t UMCpde_tree_fmt(void);

/* These first functions operate on some particular node in the fuse tree */

/* pde self-consistency check */
static inline void
UMCfuse_node_check(struct proc_dir_entry const * pde)
{
    assert(S_ISREG(pde->mode) || S_ISDIR(pde->mode) || S_ISBLK(pde->mode),
	   "pde[%s]->mode=0x%x", pde->name, pde->mode);
    assert_imply(!S_ISDIR(pde->mode), pde->child == NULL);
    assert_imply(pde == UMC_PDE_ROOT, !pde->sibling);
    assert_imply(pde->parent, pde != UMC_PDE_ROOT);
    assert_eq(pde->namelen, strlen(pde->name));
}

/* Return the number of direct child nodes of pde */
static inline uint32_t
UMCfuse_node_nchild(struct proc_dir_entry const * pde)
{
    UMCfuse_node_check(pde);
    bool isdir = S_ISDIR(pde->mode);
    uint32_t ret = 0;
    foreach_pde_child(pde, pde) {
	UMCfuse_node_check(pde);
	++ret;
    }
    assert_imply(!isdir, ret == 0);
    return ret;
}

/* Create a new node that can be added to the tree */
static struct proc_dir_entry *
UMCfuse_node_create(char const * name, umode_t mode, 
				   struct file_operations const * fops, void * data)
{
    uint32_t namelen = strlen(name);
    assert(!strchr(name, '/'), "'%s'", name);

    /* extra space for the name string -- the terminating NUL is already counted */
    struct proc_dir_entry * pde = vzalloc(sizeof(*pde) + namelen);
    memcpy(pde->name, name, namelen);
    pde->namelen = namelen;
    pde->proc_fops = fops;
    pde->data = data;
    pde->mtime = pde->atime = time(NULL);

    pde->mode = mode;
    if ((pde->mode & S_IFMT) == 0) {
	// sys_warning("mode 0%2o has no type", pde->mode);
	pde->mode |= S_IFREG;
    }
    if ((pde->mode & 0777) == 0) {
	// sys_warning("mode 0%2o has no permissions", pde->mode);
    }

    pde->owner = 0;	    /* uid=root */
    UMCfuse_node_check(pde);
    return pde;
}

/* Add the named node as a direct child of the parent pde */
static struct proc_dir_entry *
UMCfuse_node_add(char const * name, umode_t mode, struct proc_dir_entry * parent,
			       struct file_operations const * fops, void * data)
{
    assert(parent);
    assert(S_ISDIR(parent->mode));

    struct proc_dir_entry * pde = UMCfuse_node_create(name, mode, fops, data);
    pde->parent = parent;
    pde->sibling = pde->parent->child;
    pde->parent->child = pde;

    trace_verbose("created /proc %s node %s under %s",
	  S_ISDIR(mode)?"DIRECTORY":"", name, parent->name);
    return pde;
}

/* Remove the named item as a direct child of the parent pde --
 * if found, the node is removed and a pointer to it returned;
 * caller remains responsible for freeing the removed node
 */
static struct proc_dir_entry *
UMCfuse_node_remove(char const * name, struct proc_dir_entry * parent)
{
    trace_verbose("%s", name);
    assert(S_ISDIR(parent->mode));

    struct proc_dir_entry * * pdep;
    for (pdep = &parent->child; *pdep; pdep = &(*pdep)->sibling) {
	UMCfuse_node_check(*pdep);
	if (strcmp(name, (*pdep)->name)) continue;  /* name mismatch */

	if ((*pdep)->child)
	    sys_notice("%s", UMCpde_tree_fmt());

	assert_eq((*pdep)->child, NULL); /* could ENOTEMPTY, but this is internal only */

	struct proc_dir_entry * ret = *pdep;
	*pdep = (*pdep)->sibling;	/* remove from list */
	return ret;
    }

    return NULL;
}

/* Free a node after it has been removed from the tree */
static error_t
UMCfuse_node_destroy(struct proc_dir_entry * pde)
{
    if (pde->child) {
	string_t pde_str = _UMCpde_tree_fmt(pde, 1);
	sys_warning("pde %s @%p still has children:\n%s", pde->name, pde, pde_str);
	vfree(pde_str);
	return -EBUSY;
    }
    vfree(pde);
    return E_OK;
}

/* Read into buf up to size bytes starting at ofs in pde */
static ssize_t
UMCpde_node_read(struct proc_dir_entry * pde, char * buf, size_t size, off_t * ofs)
{
    error_t err;
    struct proc_inode *pi = record_alloc(pi);
    struct file * file = record_alloc(file);

    file->inode = &pi->vfs_inode;
    init_inode(file->inode, I_TYPE_PROC, pde->mode, 0, 0, -1);

    struct proc_inode * pi_check = PROC_I(file->inode);
    assert_eq(pi_check, pi);
    pi->pde = pde;

    err = pde->proc_fops->open(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->open", pde->name);
    if (err != E_OK)
	return err;

    ssize_t bytes_read = pde->proc_fops->read(file, buf, size, ofs);
    expect_rc(bytes_read, fops->read, "pde[%s]->proc_fops->read", pde->name);

    err = pde->proc_fops->release(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->release", pde->name);

    record_free(file);
    record_free(pi);

    return bytes_read;
}

/* Write from buf up to size bytes starting at ofs into pde */
static ssize_t
UMCpde_node_write(struct proc_dir_entry * pde, char const * buf, size_t size, off_t * ofs)
{
    error_t err;
    struct proc_inode *pi = record_alloc(pi);
    struct file * file = record_alloc(file);

    file->inode = &pi->vfs_inode;
    init_inode(file->inode, I_TYPE_PROC, pde->mode, 0, 0, -1);

    struct proc_inode * pi_check = PROC_I(file->inode);
    assert_eq(pi_check, pi);
    pi->pde = pde;

    err = pde->proc_fops->open(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->open", pde->name);
    if (err != E_OK)
	return err;

    mutex_unlock(&UMC_fuse_lock);   //XXXX nothing holds pde?

    ssize_t bytes_written = pde->proc_fops->write(file, buf, size, ofs);
    // expect_eq(bytes_written, size, "pde[%s]->proc_fops->write", pde->name);

    mutex_lock(&UMC_fuse_lock);

    err = pde->proc_fops->release(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->release", pde->name);

    record_free(file);
    record_free(pi);

    return bytes_written;
}

/******************************************************************************/
/* These operate on a subtree starting at pde_root, with path names relative thereto
 * (pde_root can be any position in the tree, even a leaf)
 */

/* Format a subtree into a debugging string representation */
static string_t
_UMCpde_tree_fmt(struct proc_dir_entry * pde_root, uint32_t level)
{
    struct proc_dir_entry * pde = pde_root;
    string_t ret = kasprintf(IGNORED, "%*snode@%p={name='%s' mode=0%o%s}\n", level*4, "",
			       pde, pde->name, pde->mode,
			       S_ISDIR(pde->mode) ? " (DIR)" :
			       S_ISBLK(pde->mode) ? " (BLK)" :
			       S_ISREG(pde->mode) ? " (REG)" : "");

    if (S_ISREG(pde->mode)) {
       	if (pde->proc_fops) {
	    char buf[4096]; buf[0] = '\0';
	    off_t lofs = 0;
	    UMCpde_node_read(pde_root, buf, sizeof(buf), &lofs);
	    ret = string_concat_free(ret,
			kasprintf(IGNORED, "%*s  %s\n", level*4, "", buf));
	} else {
	    ret = string_concat_free(ret,
			kasprintf(IGNORED, "%*s  %s\n", level*4, "", "(no fops)"));
	}
    }

    foreach_pde_child(pde, pde)
	ret = string_concat_free(ret, _UMCpde_tree_fmt(pde, level + 1));

    return ret;
}

/* callable under gdb to dump out the tree */
static string_t __attribute__((__unused__))
UMCpde_tree_fmt(void)
{
    struct proc_dir_entry * pde_root = UMC_PDE_ROOT;
    if (!pde_root)
	return sys_mem_zalloc(1);	/* empty string */
    return _UMCpde_tree_fmt(pde_root, 1);
}

/* Try to find a pde matching path name, starting at the given pde_root node --
 * Returns NULL if no matching node is found.
 */
static struct proc_dir_entry *
UMCfuse_lookup(struct proc_dir_entry * pde_root, sstring_t path)
{
    struct proc_dir_entry * pde;
    // trace_verbose("%s", path);
    UMCfuse_node_check(pde_root);
    assert(S_ISDIR(pde_root->mode));

    uint32_t path_ofs = 0;	/* offset of start of pathname segment in path */
    while (path[path_ofs] == '/') path_ofs++;	    /* skip '/' sequence */
    if (path[path_ofs] == '\0') {
	return pde_root;	/* path string ends at this node */
    }

    uint32_t name_ofs;		/* offset into pde's name string */
    foreach_pde_child(pde_root, pde) {
	UMCfuse_node_check(pde);
	for (name_ofs = 0 ; path[path_ofs + name_ofs] == pde->name[name_ofs]; name_ofs++) {
	    if (pde->name[name_ofs] == '\0') break;	/* end of matching strings */
	}

	if (pde->name[name_ofs] != '\0') continue;	/* mismatch -- try the next sibling */

	if (path[path_ofs + name_ofs] != '\0' && path[path_ofs + name_ofs] != '/')
	    continue;					/* mismatch -- node name was shorter */

	/* Found an entry matching this path segment */
	if (path[path_ofs + name_ofs] == '\0') {
	    return pde;		    /* this was the last path segment */
	}

	/* Descend (recursion) to lookup the next path segment with pde as root */
	return UMCfuse_lookup(pde, path + path_ofs + name_ofs);
    }

    WARN_ONCE(true, "UMCfuse_lookup failed to find %s under %s", path, pde_root->name);
    return NULL;
}

/* Lookup a path and pass back the "file mode" attributes from the corresponding PDE node */
static error_t
UMCfuse_getattr(struct proc_dir_entry * pde_root, sstring_t path, struct stat * st)
{
    trace_verbose("%s", path);
    struct proc_dir_entry * pde = UMCfuse_lookup(pde_root, path);
    if (!pde) return -ENOENT;

    assert(S_ISREG(pde->mode) || S_ISDIR(pde->mode) || S_ISBLK(pde->mode));

    st->st_mode = pde->mode;
    st->st_nlink = 1u + UMCfuse_node_nchild(pde);
#ifdef DOT_AND_DOT_DOT
    if (S_ISDIR(pde->mode))
	st->st_nlink += 2;	    /* . and .. */
#endif
    st->st_size = pde->size;
    st->st_uid = 0;		    /* root */
    st->st_atime = pde->atime;
    st->st_mtime = pde->mtime;
    st->st_rdev = pde->devt;	    // device that this node represents

    st->st_blksize = 4096;	    //XXX "preferred" block size
    // st->st_blocks		    // blocks allocated
    // st->st_ctime
    // st->st_dev		    // the device on which this file resides
    // st->st_ino		    // inode number

    /* Hack: allow users in program's group the same write access as owner */
    /* If the program's gid is zero, allow access to the adm group */
    st->st_gid = getegid();
    if (!st->st_gid) st->st_gid = 4;	/* adm */   //XXX
    if (st->st_mode & 0200) st->st_mode |= 0020;

    return E_OK;
}

/* Lookup a directory path and pass back a list of its children starting at child index ofs */
static error_t
UMCfuse_readdir(struct proc_dir_entry * pde_root, char const * path,
			    void * buf, fuse_fill_dir_t filler, off_t ofs)
{
    trace_verbose("%s ofs=%"PRIu64, path, ofs);
    struct proc_dir_entry * pde = UMCfuse_lookup(pde_root, path);
    if (!pde) return -ENOENT;
    if (!S_ISDIR(pde->mode)) return -ENOTDIR;
    pde->atime = time(NULL);
#ifdef DOT_AND_DOT_DOT
#error needs implementing
#endif
    uint32_t next_idx = ofs;
    foreach_pde_child(pde, pde) {
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

/* Lookup a file path and pass back the result of a "show" of the corresponding PDE node */
static ssize_t
UMCfuse_read(struct proc_dir_entry * pde_root, char const * path,
					char * buf, size_t size, off_t ofs)
{
    // trace_verbose("%s ofs=%"PRIu64, path, ofs);
    struct proc_dir_entry * pde = UMCfuse_lookup(pde_root, path);
    if (!pde)
	return -ENOENT;
    if (S_ISDIR(pde->mode))
	return -EISDIR;
    assert(pde->proc_fops);

    ssize_t ret;
    if (S_ISBLK(pde->mode)) {
	//XXXXXX
    } else {
	buf[0] = '\0';
	ret = UMCpde_node_read(pde, buf, size, &ofs);	//XXXXX check &ofs
    }

    pde->atime = time(NULL);
    trace_verbose("READ %s REPLY len=%"PRIu64" '%.*s'", path, ret, (uint32_t)ret, buf);
    return ret;
}

/* Lookup a file path and call the write function of the corresponding PDE node */
static ssize_t
UMCfuse_write(struct proc_dir_entry * pde_root, char const * path,
				    char const * buf, size_t size, off_t ofs)
{
    trace("WRITE %s '%.*s'", path, (int)size, buf);
    struct proc_dir_entry * pde = UMCfuse_lookup(pde_root, path);
    if (!pde)
	return -ENOENT;
    if (S_ISDIR(pde->mode))
	return -EISDIR;
    assert(pde->proc_fops);

    /* These nodes aren't supposed to be writable, but superuser can still get here */
    if (!pde->proc_fops->write)
	return -EPERM;

    ssize_t ret;
    if (S_ISBLK(pde->mode)) {
	//XXXXXX
    } else {
	ret = UMCpde_node_write(pde, buf, size, &ofs);	//XXXXX check &ofs
    }

    pde->mtime = time(NULL);
    trace_verbose("WRITE %s REPLY len=%"PRIu64" '%.*s'", path, ret, (uint32_t)ret, buf);
    return ret;
}

/******************************************************************************/
/* These are called by FUSE to implement the filesystem functions */

static error_t
UMC_fuse_getattr(sstring_t path, struct stat * st)
{
    mutex_lock(&UMC_fuse_lock);
    error_t err = UMCfuse_getattr(UMC_PDE_ROOT, path, st);
    mutex_unlock(&UMC_fuse_lock);
    return err;
}

static error_t
UMC_fuse_readdir(char const * path, void * buf,
		 fuse_fill_dir_t filler, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&UMC_fuse_lock);
    error_t err = UMCfuse_readdir(UMC_PDE_ROOT, path, buf, filler, ofs);
    mutex_unlock(&UMC_fuse_lock);
    return err;
}

static int
UMC_fuse_open(char const * path, struct fuse_file_info * fi)
{
    trace_verbose("%s", path);

    mutex_lock(&UMC_fuse_lock);
    struct proc_dir_entry * pde = UMCfuse_lookup(UMC_PDE_ROOT, path);
    mutex_unlock(&UMC_fuse_lock);

    if (!pde) return -ENOENT;
    if (S_ISDIR(pde->mode)) return -EISDIR;

    fi->nonseekable = true; /* we have the open function so we can set this */

    fi->direct_io = true;   /* should be superfluous with "-o direct_io" */

    return E_OK;
}

static int
UMC_fuse_read(char const * path, char * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&UMC_fuse_lock);
    ssize_t ret = UMCfuse_read(UMC_PDE_ROOT, path, buf, size, ofs);
    mutex_unlock(&UMC_fuse_lock);
    return ret;
}

static int
UMC_fuse_write(char const * path, char const * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&UMC_fuse_lock);
    ssize_t ret = UMCfuse_write(UMC_PDE_ROOT, path, buf, size, ofs);
    mutex_unlock(&UMC_fuse_lock);
    return ret;
}

static struct fuse_operations const pde_ops = {
    .getattr	= UMC_fuse_getattr,
    .readdir	= UMC_fuse_readdir,
    .open	= UMC_fuse_open,
    .read	= UMC_fuse_read,
    .write	= UMC_fuse_write,
};

/******************************************************************************/

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
	_unconstify(mount_point),

	//"--help",
	//"--version",
	//"-d",			    /* debug, implies -f */
	"-f",			    /* foreground (else daemonizes) */
	"-s",			    /* single-threaded */

	"-o", "allow_other",
	"-o", "auto_unmount",
	"-o", "default_permissions",
	"-o", "subtype=pde",
	"-o", "direct_io",
	"-o", "sync_read",
	"-o", "atomic_o_trunc",	    /* avoid calls to truncate */

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
    // trace_init(true, false);
    assert(!UMC_FUSE_THREAD);
    assert(!UMC_PDE_ROOT);
    assert(mountpoint);

    mount_point = mountpoint;

    //XXXX should strrchr('/') this or treat root name special ?
    while (*mountpoint == '/')
	mountpoint++;		/* skip initial '/' sequence for the nodename */
    if (*mountpoint == '\0') {
	return -EINVAL;
    }
    UMC_PDE_ROOT = UMCfuse_node_create(mountpoint, PROC_ROOT_UMODE, NULL, NULL);

    UMC_PDE_PROC = pde_create("proc", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_DEV = pde_create("dev", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_SYS = pde_create("sys", PROC_DIR_UMODE, UMC_PDE_ROOT, NULL, NULL);
    UMC_PDE_MOD = pde_create("module", PROC_DIR_UMODE, UMC_PDE_SYS, NULL, NULL);

    /* Create the mount point for the fuse filesystem */
    string_t cmd = kasprintf(IGNORED, "/bin/mkdir -p %s; chmod 777 %s",
			       mount_point, mount_point);
    int rc = system(cmd);
    expect_noerr(rc, "system(\"%s\")", cmd);
    kfree(cmd);

    sys_notice("created %s fuse root @%p -- starting fuse service", mount_point, UMC_PDE_ROOT);

    UMC_FUSE_THREAD = sys_thread_alloc(UMC_fuse_run, NULL, kstrdup("UMC_fuse", IGNORED));

    error_t err = sys_thread_start(UMC_FUSE_THREAD);
    expect_noerr(err, "sys_thread_start UMC_FUSE_THREAD");
    if (err != E_OK) {
	UMCfuse_node_destroy(UMC_PDE_ROOT);
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

    pde_remove("module", UMC_PDE_SYS); UMC_PDE_MOD = NULL;
    pde_remove("sys", UMC_PDE_ROOT); UMC_PDE_SYS = NULL;
    pde_remove("dev", UMC_PDE_ROOT); UMC_PDE_DEV = NULL;
    pde_remove("proc", UMC_PDE_ROOT); UMC_PDE_PROC = NULL;

    UMCfuse_node_destroy(UMC_PDE_ROOT); UMC_PDE_ROOT = NULL;

    return E_OK;
}

error_t
UMC_fuse_stop(void)
{
    /* If we prod the fuse thread it will return from fuse_main to UMC_fuse_run */
    sys_thread_t fusethread = UMC_FUSE_THREAD;
    if (!fusethread) return -EINVAL;

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

/******************************************************************************/
/* These are called by the application program to build and
 * operate on a PDE tree rooted at the global single-instance PDE_ROOT.
 */

/* Add an entry to the tree directly under parent -- attaches to UMC_PDE_PROC if parent is NULL */
struct proc_dir_entry *
pde_create(char const * name, umode_t mode, struct proc_dir_entry * parent,
				    struct file_operations const * fops, void * data)
{
    if (!parent)
	parent = UMC_PDE_PROC;

    mutex_lock(&UMC_fuse_lock);
    struct proc_dir_entry * ret = UMCfuse_node_add(name, mode, parent, fops, data);
    mutex_unlock(&UMC_fuse_lock);

    return ret;
}

/* Remove and destroy an entry from directly under parent */
error_t
pde_remove(char const * name, struct proc_dir_entry * parent)
{
    if (!parent)
	parent = UMC_PDE_PROC;

    mutex_lock(&UMC_fuse_lock);
    struct proc_dir_entry * node = UMCfuse_node_remove(name, parent);
    mutex_unlock(&UMC_fuse_lock);

    if (!node) {
	sys_warning("proc_dir_entry %s not found in %s", name, parent->name);
	return -ENOENT;
    }

    UMCfuse_node_destroy(node);
    return E_OK;
}

#if 0
/* Lookup an entry */
struct proc_dir_entry *
pde_lookup(char const * name, struct proc_dir_entry * parent)
{
    if (!parent)
	parent = UMC_PDE_ROOT;

    mutex_lock(&UMC_fuse_lock);
    //XXX hold?
    struct proc_dir_entry * pde = UMCfuse_lookup(parent, path);
    mutex_unlock(&UMC_fuse_lock);

    return node;
}
#endif

struct proc_dir_entry *
UMC_fuse_module_mkdir(char * modname)
{
    struct proc_dir_entry * pde_parent = UMC_PDE_ROOT;
    pde_parent = UMCfuse_lookup(pde_parent, "sys");
    assert(pde_parent);
    pde_parent = UMCfuse_lookup(pde_parent, "module");
    assert(pde_parent);
    pde_parent = pde_create(modname, PROC_DIR_UMODE, pde_parent, NULL, NULL);
    assert(pde_parent);
    return pde_create("parameters", PROC_DIR_UMODE, pde_parent, NULL, NULL);
}

error_t
UMC_fuse_module_rmdir(char * modname)
{
    struct proc_dir_entry * pde_mymodule;
    struct proc_dir_entry * pde_parent = UMC_PDE_ROOT;
    pde_parent = UMCfuse_lookup(pde_parent, "sys");
    assert(pde_parent);
    pde_parent = UMCfuse_lookup(pde_parent, "module");
    assert(pde_parent);
    pde_mymodule = UMCfuse_lookup(pde_parent, modname);
    if (!pde_mymodule)
	return ENOENT;
    pde_remove("parameters", pde_mymodule);
    pde_remove(modname, pde_parent);
    return E_OK;
}

/* These are for reading and writing "module_param_named" global variables */
/* They appear under /sys/module/THIS_MODULE->name/parameters */
//XXXX You can write the variables, but nothing will happen unless someone then looks at them...

static ssize_t
module_param_write(struct file * file, char const * buf, size_t writesize, loff_t * ofs)
{
    if (writesize == 0) {
	return -EINVAL;
    }
    assert(buf);
    assert_eq(*ofs, 0);

    errno = 0;
    long v = strtol(buf, NULL, 0);
    if (errno != 0) {
	return -EINVAL;
    }
    if (v & ~0xffffffffL) {
	return -ERANGE;
    }

    struct proc_dir_entry * pde = PROC_I(file->inode)->pde;
    UMCfuse_node_check(pde);
    *(int *)pde->data = v;
    
    return (ssize_t)writesize;
}

static ssize_t
module_param_read(struct file * file, void * buf, size_t readsize, loff_t * ofs)
{
    if (readsize == 0) {
	return -EINVAL;
    }
    assert(buf);
    if (*ofs != 0) return 0;	    //XXX good enough?

    struct proc_dir_entry * pde = PROC_I(file->inode)->pde;
    UMCfuse_node_check(pde);
    int nchar = snprintf(buf, readsize, "%d 0x%x\n",
			 *(int *)pde->data, *(int *)pde->data);
    if ((size_t)nchar > readsize) nchar = readsize;

    return nchar;
}

static error_t
module_param_open(struct inode * inode, struct file * file)
{
    return E_OK;
}

static error_t
module_param_release(struct inode * inode, struct file * file)
{
    return E_OK;
}

struct file_operations module_fops = {
    .open = module_param_open,
    .release = module_param_release,
    .read = module_param_read,
    .write = module_param_write,
};

struct proc_dir_entry *
UMC_module_param_create(char const * name, void * varp, size_t size,
			umode_t mode, struct module * owner)
{
    assert_eq(size, sizeof(int));	//XXX

    /* e.g. /UMCroot/sys/module/scsi_tgt/parameters/xxx */
    struct proc_dir_entry * parent = UMC_PDE_MOD;
    assert(parent);
    parent = UMCfuse_lookup(parent, owner->name);
    if (!parent)
	return NULL;
    parent = UMCfuse_lookup(parent, "parameters");
    if (!parent)
	return NULL;

    struct proc_dir_entry * ret = pde_create(name, mode, parent, &module_fops, varp);
    return ret;
}

error_t
UMC_module_param_remove(char const * name, struct module * owner)
{
    struct proc_dir_entry * parent = UMC_PDE_MOD;
    assert(parent);
    parent = UMCfuse_lookup(parent, owner->name);
    if (!parent)
	return ENOENT;
    parent = UMCfuse_lookup(parent, "parameters");
    if (!parent)
	return ENOENT;

    return pde_remove(name, parent);
}

/* Entries for /dev */

struct proc_dir_entry *
UMC_fuse_dev_add(const char * name, dev_t devt, umode_t mode)
{
    struct proc_dir_entry * ret = pde_create(name, mode, UMC_PDE_DEV, NULL, NULL);
    ret->devt = devt;
    return ret;
}

error_t
UMC_fuse_dev_remove(const char * name)
{
    return pde_remove(name, UMC_PDE_DEV);
}
