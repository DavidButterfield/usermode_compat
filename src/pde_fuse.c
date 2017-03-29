/* pde_fuse.c
 * Usermode emulation for kernel-code /proc consumers running in usemode, using FUSE
 * Copyright 2016 David A. Butterfield
 *
 * proc_create_data() and remove_proc_entry() are used by the program to build a tree of
 * "/proc directory entries" representing the filesystem structure.
 *
 * pde_fuse_getattr, pde_fuse_readdir, pde_fuse_open, pde_fuse_read, and pde_fuse_write
 * are called by FUSE when an external application accesses or writes one of our nodes.
 *
 * pde_fuse_start, pde_fuse_stop, and pde_fuse_exit initialize and/or free resources.
 */
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64	/* fuse seems to want this even on 64-bit */
#include <fuse.h>

#define NAME PDE_FUSE
#include "usermode_lib.h"
#include "sys_debug.h"

/* These first functions operate on some particular node in the PDE (proc_dir_entry) tree */

/* PDE self-consistency check */
static inline void
pde_node_check(struct proc_dir_entry const * pde)
{
    assert(S_ISREG(pde->mode) || S_ISDIR(pde->mode),
	   "pde[%s]->mode=0x%x", pde->name, pde->mode);
    assert_imply(!S_ISDIR(pde->mode), pde->child == NULL);
    assert_eq(pde->namelen, strlen(pde->name));
}

/* Return the number of direct child nodes of pde */
static inline uint32_t
pde_node_nchild(struct proc_dir_entry const * pde)
{
    pde_node_check(pde);
    bool isdir = S_ISDIR(pde->mode);
    uint32_t ret = 0;
    for (pde = pde->child; pde; pde = pde->sibling) {
	pde_node_check(pde);
	++ret;
    }
    assert_imply(!isdir, ret == 0);
    return ret;
}

/* Create a new node and add it as a direct child of the parent pde */
static struct proc_dir_entry *
pde_node_create(char const * name, umode_t mode, 
				   struct file_operations const * fops, void * data)
{
    uint32_t namelen = strlen(name);

    /* extra space for the name string -- the terminating NUL is already counted */
    struct proc_dir_entry * pde = vzalloc(sizeof(*pde) + namelen);
    strcpy(pde->name, name);
    pde->namelen = namelen;
    pde->proc_fops = fops;
    pde->data = data;
    pde->mtime = pde->atime = time(NULL);

    pde->mode = mode;
    if ((pde->mode & S_IFMT) == 0) pde->mode |= S_IFREG;
    if ((pde->mode & 0777) == 0) pde->mode |= S_IRUGO; 

    // pde->owner = XXX;
    pde_node_check(pde);
    return pde;
}

/* Add the named item as a direct child of the parent pde */
static struct proc_dir_entry *
pde_node_add(char const * name, umode_t mode, struct proc_dir_entry * parent,
			       struct file_operations const * fops, void * data)
{
    assert(parent);
    assert(S_ISDIR(parent->mode));

    struct proc_dir_entry * pde = pde_node_create(name, mode, fops, data);
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
pde_node_remove(char const * name, struct proc_dir_entry * parent)
{
    trace_verbose("%s", name);
    assert(S_ISDIR(parent->mode));

    struct proc_dir_entry * * pdep;
    for (pdep = &parent->child; *pdep; pdep = &(*pdep)->sibling) {
	pde_node_check(*pdep);
	if (strcmp(name, (*pdep)->name)) continue;  /* name mismatch */

	assert_eq((*pdep)->child, NULL); /* could ENOTEMPTY, but this is internal only */

	struct proc_dir_entry * ret = *pdep;
	*pdep = (*pdep)->sibling;	/* remove from list */
	return ret;
    }

    return NULL;
}

static ssize_t
pde_node_fmt(struct proc_dir_entry * pde, char * buf, size_t size, off_t * lofsp)
{
    struct file * const file = _file_alloc(-1, I_TYPE_PROC, pde->mode, 0, 0);
    PROC_I(file->inode)->pde = pde;

    errno_t err;

    err = pde->proc_fops->open(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->open", pde->name);
    if (err != E_OK) return err;

    ssize_t bytes_read = pde->proc_fops->read(file, buf, size, lofsp);
    expect_rc(bytes_read, fops->read, "pde[%s]->proc_fops->read", pde->name);

    err = pde->proc_fops->release(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->release", pde->name);

    record_free(file);

    return bytes_read;
}

/******************************************************************************/
/* These operate on a subtree starting at pde_root, with path names relative thereto
 * (pde_root can be any position in the tree, even a leaf)
 */

/* Format a subtree into a debugging string representation */
static string_t
_pde_tree_fmt(struct proc_dir_entry * pde_root, uint32_t level)
{
    struct proc_dir_entry * pde = pde_root;
    string_t ret = kasprintf(IGNORED, "%*snode@%p={name='%s' mode=0%o%s}\n", level*4, "",
			       pde, pde->name, pde->mode,
			       S_ISDIR(pde->mode) ? " (DIR)" :
			       S_ISREG(pde->mode) ? " (REG)" : "");

    if (S_ISREG(pde->mode)) {
       	if (pde->proc_fops) {
	    char buf[4096]; buf[0] = '\0';
	    off_t lofs = 0;
	    pde_node_fmt(pde_root, buf, sizeof(buf), &lofs);
	    ret = string_concat_free(ret,
			kasprintf(IGNORED, "%*s  %s\n", level*4, "", buf));
	} else {
	    ret = string_concat_free(ret,
			kasprintf(IGNORED, "%*s  %s\n", level*4, "", "(no fops)"));
	}
    }

    for (pde = pde->child; pde; pde = pde->sibling) {
	ret = string_concat_free(ret, _pde_tree_fmt(pde, level + 1));
    }

    return ret;
}

/* Try to find a pde matching path name, starting at the given pde_root node --
 * Returns NULL if no matching node is found
 */
static struct proc_dir_entry *
pde_lookup(struct proc_dir_entry * pde_root, sstring_t path)
{
    // trace_verbose("%s", path);
    pde_node_check(pde_root);
    assert(S_ISDIR(pde_root->mode));
    assert_eq(path[0], '/');

    struct proc_dir_entry * pde = pde_root;

    uint32_t path_ofs = 0;	/* offset of start of pathname segment in path */
    while (path[path_ofs] == '/') path_ofs++;	    /* skip '/' sequence */
    if (path[path_ofs] == '\0') {
	return pde;		    /* path string ends at this node */
    }

    uint32_t name_ofs;		/* offset into pde's name string */
    for (pde = pde_root->child; pde; pde = pde->sibling) {
	pde_node_check(pde);
	for (name_ofs = 0 ; path[path_ofs + name_ofs] == pde->name[name_ofs]; name_ofs++) {
	    if (pde->name[name_ofs] == '\0') break;	/* end of matching strings */
	}

	if (pde->name[name_ofs] != '\0') continue;	/* mismatch -- try the next sibling */

	if (path[path_ofs + name_ofs] != '\0' && path[path_ofs + name_ofs] != '/') continue;

	/* Found an entry matching this path segment */
	if (path[path_ofs + name_ofs] == '\0') {
	    return pde;		    /* this was the last path segment */
	}

	/* Descend (recursion) to lookup the next path segment with pde as root */
	return pde_lookup(pde, path + path_ofs + name_ofs);
    }

    WARN_ONCE(true, "pde_lookup failed to find %s under %s", path, pde_root->name);
    return NULL;
}

/* Lookup a path and pass back the "file mode" attributes from the corresponding PDE node */
static errno_t
pde_getattr(struct proc_dir_entry * pde_root, sstring_t path, struct stat * st)
{
    trace_verbose("%s", path);
    struct proc_dir_entry * pde = pde_lookup(pde_root, path);
    if (!pde) return -ENOENT;

    assert(S_ISREG(pde->mode) || S_ISDIR(pde->mode));

    st->st_mode = pde->mode;
    st->st_nlink = 1 + S_ISDIR(pde->mode) + pde_node_nchild(pde);
    st->st_size = 4096;	//XXXX	What should go here?
    st->st_uid = 0;		    /* root */
    st->st_atime = pde->atime;
    st->st_mtime = pde->mtime;

    /* Hack: allow users in program's group the same write access as owner */
    /* If the program's gid is zero, allow access to the adm group */
    st->st_gid = getegid();
    if (!st->st_gid) st->st_gid = 4;	/* adm */   //XXX
    if (st->st_mode & 0200) st->st_mode |= 0020;

    return E_OK;
}

/* Lookup a directory path and pass back a list of its children */
static errno_t
pde_readdir(struct proc_dir_entry * pde_root, char const * path,
			    void * buf, fuse_fill_dir_t filler, off_t ofs)
{
    trace_verbose("%s ofs=%"PRIu64, path, ofs);
    struct proc_dir_entry * pde = pde_lookup(pde_root, path);
    if (!pde) return -ENOENT;
    if (!S_ISDIR(pde->mode)) return -ENOTDIR;
    pde->atime = time(NULL);

    uint32_t next_idx = ofs;
    for (pde = pde->child; pde; pde = pde->sibling) {
	pde_node_check(pde);
	if (ofs) {
	    --ofs;
	    continue;	/* skip over the first (ofs) items without processing */
	}
	trace_verbose("    %s child=%s", path, pde->name);
	if (filler(buf, pde->name, NULL, ++next_idx)) break;/* buffer full */
    }

    return E_OK;
}

/* Lookup a file path and pass back the result of a "show" of the corresponding PDE node */
static ssize_t
pde_read(struct proc_dir_entry * pde_root, char const * path,
					char * buf, size_t size, off_t ofs)
{
    // trace_verbose("%s ofs=%"PRIu64, path, ofs);
    struct proc_dir_entry * pde = pde_lookup(pde_root, path);
    if (!pde) return -ENOENT;
    if (S_ISDIR(pde->mode)) return -EISDIR;
    assert(pde->proc_fops);

    pde->atime = time(NULL);
    buf[0] = '\0';
    ssize_t ret = pde_node_fmt(pde, buf, size, &ofs);

    trace_verbose("READ %s REPLY len=%"PRIu64" '%.*s'", path, ret, (uint32_t)ret, buf);
    return ret;
}

DEFINE_MUTEX(pde_fuse_lock);		    //XXX nasty big lock could be fixed

/* Lookup a file path and call the write function of the corresponding PDE node */
static ssize_t
pde_write(struct proc_dir_entry * pde_root, char const * path,
				    char const * buf, size_t size, off_t ofs)
{
    // trace("%s size=%"PRIu64" ofs=%u", path, size, (uint32_t)ofs);
    trace("WRITE %s '%.*s'", path, (int)size, buf);

    struct proc_dir_entry * pde = pde_lookup(pde_root, path);
    if (!pde) return -ENOENT;
    if (S_ISDIR(pde->mode)) return -EISDIR;

    /* These nodes aren't supposed to be writable, but superuser can still get here */
    if (!pde->proc_fops->write) return -EPERM;

    struct file * const file = record_alloc(file);
    file->inode = &file->inode_s;
    PROC_I(file->inode)->pde = pde;
    int err;

    err = pde->proc_fops->open(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->open", pde->name);
    if (err != E_OK) return err;

    mutex_unlock(&pde_fuse_lock);

    ssize_t ret = pde->proc_fops->write(file, buf, size, &ofs);
    expect_eq(ret, size, "pde[%s]->proc_fops->write", pde->name);

    mutex_lock(&pde_fuse_lock);

    err = pde->proc_fops->release(file->inode, file);
    expect_noerr(err, "pde[%s]->proc_fops->release", pde->name);

    record_free(file);

    pde->mtime = time(NULL);
    return ret;
}

/******************************************************************************/
/* These are called by FUSE to implement the filesystem functions */

static struct proc_dir_entry * PDE_ROOT;    //XXX limitation: single instance


static errno_t
pde_fuse_getattr(sstring_t path, struct stat * st)
{
    mutex_lock(&pde_fuse_lock);
    errno_t err = pde_getattr(PDE_ROOT, path, st);
    mutex_unlock(&pde_fuse_lock);
    return err;
}

static errno_t
pde_fuse_readdir(char const * path, void * buf,
		 fuse_fill_dir_t filler, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&pde_fuse_lock);
    errno_t err = pde_readdir(PDE_ROOT, path, buf, filler, ofs);
    mutex_unlock(&pde_fuse_lock);
    return err;
}

static int
pde_fuse_open(char const * path, struct fuse_file_info * fi)
{
    trace_verbose("%s", path);

    mutex_lock(&pde_fuse_lock);
    struct proc_dir_entry * pde = pde_lookup(PDE_ROOT, path);
    mutex_unlock(&pde_fuse_lock);

    if (!pde) return -ENOENT;
    if (S_ISDIR(pde->mode)) return -EISDIR;

    fi->nonseekable = true; /* we have the open function so we can set this */

    fi->direct_io = true;   /* should be superfluous with "-o direct_io" */

    return E_OK;
}

static int
pde_fuse_read(char const * path, char * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&pde_fuse_lock);
    ssize_t ret = pde_read(PDE_ROOT, path, buf, size, ofs);
    mutex_unlock(&pde_fuse_lock);
    return ret;
}

static int
pde_fuse_write(char const * path, char const * buf, size_t size, off_t ofs, struct fuse_file_info * fi)
{
    mutex_lock(&pde_fuse_lock);
    ssize_t ret = pde_write(PDE_ROOT, path, buf, size, ofs);
    mutex_unlock(&pde_fuse_lock);
    return ret;
}

static struct fuse_operations const pde_ops = {
    .getattr	= pde_fuse_getattr,
    .readdir	= pde_fuse_readdir,
    .open	= pde_fuse_open,
    .read	= pde_fuse_read,
    .write	= pde_fuse_write,
};

/******************************************************************************/

static string_t __unused
pde_tree_fmt(struct proc_dir_entry * pde_root)
{
    if (pde_root == NULL) pde_root = PDE_ROOT;
    if (!pde_root->child) return sys_mem_zalloc(1); /* empty string */
    return _pde_tree_fmt(pde_root->child, 1);
}

static volatile sys_thread_t PDE_FUSE_THREAD;
char * FUSE_PROC_ROOT;

extern void sigint_hack(void);

/* Here starting up on the pde_fuse thread */
static int
pde_fuse_run(void * unused)
{
    assert_eq(unused, NULL);
    assert_eq(sys_thread_current(), PDE_FUSE_THREAD);
    assert(FUSE_PROC_ROOT);

    /* XXXX setup pde_fuse "current" -- change this to start a "kernel thread" */
    struct task_struct * task = UMC_current_alloc();
    UMC_current_init(task, sys_thread_current(), (void *)pde_fuse_run, unused,
		     kstrdup("pde_fuse thread", IGNORED));
    UMC_current_set(task);

    char /*const*/ * pde_fuse_argv[] = {
	"fuse_main",		    /* argv[0] */
	FUSE_PROC_ROOT,		    /* mount point */

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

    int pde_fuse_argc = ARRAY_SIZE(pde_fuse_argv) - 1;

    sys_notice("pde_fuse thread @%p starts up on tid=%u",
	       sys_thread_current(), sys_thread_num(sys_thread_current()));

    int ret = fuse_main(pde_fuse_argc, pde_fuse_argv, &pde_ops, NULL);

    if (ret == E_OK) {
	sys_notice("fuse_main returned %d -- FUSE thread exits", ret);
    } else {
	sys_warning("fuse_main returned %d -- FUSE thread exits", ret);
    }

    /* XXX Hack: Sometimes the fuse thread steals the SIGINT and the MTE
     *     sigfd_handler can't read the signal.  Anyway, the fuse thread
     *     should not be exiting unless the program is shutting down.
     */     
    sigint_hack();
    
    UMC_current_free(current);
    UMC_current_set(NULL);

    assert_eq(sys_thread_current(), PDE_FUSE_THREAD);
    PDE_FUSE_THREAD = NULL;
    sys_thread_exit(0);
}

/* Call once from any thread to initialize PDE_ROOT and start PDE_FUSE_THREAD */
errno_t
pde_fuse_start(char * mountpoint)
{
    // trace_init(true, false);
    assert(!PDE_FUSE_THREAD);
    assert(!PDE_ROOT);
    assert(!FUSE_PROC_ROOT);
    assert(mountpoint);
    FUSE_PROC_ROOT = mountpoint;

    PDE_ROOT = pde_node_create("PDE_ROOT", PROC_ROOT_UMODE, NULL, NULL);

    // XXX lazy
    string_t cmd = kasprintf(IGNORED, "/bin/mkdir -p %s; chmod 777 %s",
			       FUSE_PROC_ROOT, FUSE_PROC_ROOT);
    int rc = system(cmd);
    expect_noerr(rc, "system(\"%s\")", cmd);
    kfree(cmd);

    sys_notice("created /proc PDE_ROOT @%p -- starting fuse service", PDE_ROOT);

    PDE_FUSE_THREAD = sys_thread_alloc(pde_fuse_run, NULL, kstrdup("pde_fuse", IGNORED));

    errno_t err = sys_thread_start(PDE_FUSE_THREAD);
    expect_noerr(err, "sys_thread_start PDE_FUSE_THREAD");
    if (err != E_OK) {
	vfree(PDE_ROOT);
	PDE_ROOT = NULL;
    }

    return err;
}

errno_t
pde_fuse_exit(void)
{
    trace();
    assert(PDE_ROOT);

    /* Need to shutdown fuse thread before calling pde_fuse_exit() */
    if (PDE_FUSE_THREAD) {
	sys_warning("pde_fuse_exit called while PDE_FUSE_THREAD still active");
	return -EBUSY;
    }

    /* Need to remove PDE tree members before root */
    if (PDE_ROOT->child) {
	sys_warning("pde_fuse_exit called while PDE_ROOT still has children");
	return -EBUSY;
    }

    vfree(PDE_ROOT);
    PDE_ROOT = NULL;

    return E_OK;
}

errno_t
pde_fuse_stop(void)
{
    /* If we prod the fuse thread it will return from fuse_main to pde_fuse_run */
    sys_thread_t fusethread = PDE_FUSE_THREAD;
    if (!fusethread) return -EINVAL;

    trace("tkill %d, SIGTERM", fusethread->tid);
    int rc = syscall(SYS_tkill, fusethread->tid, SIGTERM);
    expect_eq(rc, 0, "tgkill fuse tid=%u errno=%d '%s'",
		     fusethread->tid, errno, strerror(errno));

    /* Wait for fuse thread to return to pde_fuse_run */
    int max = 1000;
    while (PDE_FUSE_THREAD) {
	if (!max--) {
	    sys_warning("pde_fuse thread didn't exit timely");
	    return -EBUSY;
	}
	usleep(1000);
    }

    return E_OK;
}

/******************************************************************************/
/* These are called by the application program to build and
	operate on a PDE tree rooted at the global single-instance PDE_ROOT */

/* Add an entry to the tree directly under parent -- attaches to PDE_ROOT if parent is NULL */
struct proc_dir_entry *
pde_create(char const * name, umode_t mode, struct proc_dir_entry * parent,
				    struct file_operations const * fops, void * data)
{
    mutex_lock(&pde_fuse_lock);

    if (!parent) parent = PDE_ROOT;
    struct proc_dir_entry * ret = pde_node_add(name, mode, parent, fops, data);
    mutex_unlock(&pde_fuse_lock);
    return ret;
}

/* Remove an entry from directly under parent -- caller responsible to free the node */
struct proc_dir_entry *
pde_remove(char const * name, struct proc_dir_entry * parent)
{
    mutex_lock(&pde_fuse_lock);

    if (!parent) parent = PDE_ROOT;
    struct proc_dir_entry * node = pde_node_remove(name, parent);

    mutex_unlock(&pde_fuse_lock);

    if (node == NULL) {
	sys_warning("proc_dir_entry %s not found in %s", name, parent->name);
    }
    return node;
}

/* These are for reading and writing "module_param_named" global variables */
//XXXX You can write the variables, but nothing will happen unless someone then looks at them...

static ssize_t
module_param_write(struct file * file, char const * buf, size_t writesize, loff_t * lofsp)
{
    if (writesize == 0) {
	return -EINVAL;
    }
    assert(buf);
    assert_eq(*lofsp, 0);

    errno = 0;
    long v = strtol(buf, NULL, 0);
    if (errno != 0) {
	return -EINVAL;
    }
    if (v & ~0xffffffffL) {
	return -ERANGE;
    }

    struct proc_dir_entry * pde = PROC_I(file->inode)->pde;
    pde_node_check(pde);
    *(int *)pde->data = v;
    
    return writesize;
}

static ssize_t
module_param_read(struct file * file, void * buf, size_t readsize, loff_t * lofsp)
{
    if (readsize == 0) {
	return -EINVAL;
    }
    assert(buf);
    if (*lofsp != 0) return 0;	    //XXX good enough?

    struct proc_dir_entry * pde = PROC_I(file->inode)->pde;
    pde_node_check(pde);
    int nchar = snprintf(buf, readsize, "%d 0x%x\n",
			 *(int *)pde->data, *(int *)pde->data);
    if ((size_t)nchar > readsize) nchar = readsize;

    return nchar;
}

static errno_t
module_param_open(struct inode * inode, struct file * file)
{
    return E_OK;
}

static errno_t
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
pde_module_param_create(char const * name, void * varp, size_t size, umode_t mode)
{
    assert_eq(size, sizeof(int));
    return pde_create(name, mode, NULL, &module_fops, varp);
}

struct proc_dir_entry *
pde_module_param_remove(char const * name)
{
    return pde_remove(name, NULL);
}
