/* UMC_fuse_proc.c -- use fuse to implement /proc
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * These functions are for reading and writing "module_param_named" global
 * variables.  They appear under /sys/module/THIS_MODULE->name/parameters
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>

#include "UMC_fuse_proc.h"
#include "fuse_tree.h"

#define trace_cb(args...)		printk(args)
#define trace_fuse_thread(args...)	printk(args)

static ssize_t
fuse_pde_read(uintptr_t pde_arg, void * buf, size_t iosize, off_t ofs)
{
    struct proc_dir_entry * pde = (void *)pde_arg;
    return pde->proc_fops->read(pde->data, buf, iosize, &ofs);
}

static ssize_t
fuse_pde_write(uintptr_t pde_arg, const char * buf, size_t iosize, off_t ofs)
{
    struct proc_dir_entry * pde = (void *)pde_arg;
    return pde->proc_fops->write(pde->data, buf, iosize, &ofs);
}

static struct fuse_node_ops fuse_pde_ops = {
    .read = fuse_pde_read,
    .write = fuse_pde_write,
};

struct proc_dir_entry *
fuse_pde_add(const char * name, struct proc_dir_entry * parent, umode_t mode,
		const struct file_operations * proc_fops, void * data)
{
    struct proc_dir_entry * pde = NULL;
    fuse_node_t fnode;
    fuse_node_t parent_fnode;

    if (parent)
	parent_fnode = parent->fnode;
    else
	parent_fnode = fuse_node_lookup("/proc");

    if (!parent_fnode)
	return NULL;

    fnode = fuse_node_add(name, parent->fnode, mode, &fuse_pde_ops, (uintptr_t)pde);
    if (fnode) {
	pde = record_alloc(pde);
	pde->fnode = fnode;
	pde->proc_fops = proc_fops;
	pde->data = data;
    }

    return pde;
}

struct proc_dir_entry *
fuse_pde_mkdir(const char * name, struct proc_dir_entry * parent)
{
    struct proc_dir_entry * pde = NULL;
    fuse_node_t fnode;
    fuse_node_t parent_fnode;

    if (parent)
	parent_fnode = parent->fnode;
    else
	parent_fnode = fuse_node_lookup("/sys/modules");

    if (!parent_fnode)
	return NULL;

    fnode = fuse_tree_mkdir(name, parent_fnode);
    if (fnode) {
	pde = record_alloc(pde);
	pde->fnode = fnode;
    }

    return pde;
}

error_t
fuse_pde_remove(const char * name, struct proc_dir_entry * parent)
{
    error_t err;
    uintptr_t pde_uip;
    struct proc_dir_entry * pde;
    fuse_node_t fnode = fuse_node_lookupat(parent->fnode, name);
    if (!fnode)
	return -ENOENT;

    pde = (void *)(pde_uip = fuse_node_data_get(fnode));
    err =  fuse_node_remove(name, fnode);
    if (!err)
	record_free(pde);

    return err;
}

/******************************************************************************/

/* Describe the location of a module param variable */
struct varloc {
    void	      * addr;
    size_t		size;
    fuse_node_t		fnode;
};

static ssize_t
fuse_modparm_read(uintptr_t varloc_arg, void * buf, size_t iosize, off_t ofs)
{
    struct varloc * varloc = (void *)varloc_arg;
    long long data = 0;

    trace_cb("iosize=%lu, ofs=%lu", iosize, ofs);
    assert_ne(buf, 0);
    verify_ge(sizeof(data), varloc->size);

    if (iosize == 0)
	return -EINVAL;

    if (ofs)
	return 0;	    //XXX good enough?

    memcpy(&data, varloc->addr, varloc->size);
    //XXXX big endian?  data = data >> (8 * ((sizeof(data) - varloc->size)));
    
    size_t nchar = snprintf(buf, iosize, "%lld\n", data);
    if (nchar > iosize)
	nchar = iosize;

    return (ssize_t)nchar;
}

static ssize_t
fuse_modparm_write(uintptr_t varloc_arg, const char * buf, size_t iosize, off_t ofs)
{
    struct varloc * varloc = (void *)varloc_arg;
    long long data;

    trace_cb("iosize=%lu, ofs=%lu", iosize, ofs);
    assert_ne(buf, 0);
    verify_ge(sizeof(data), varloc->size);

    if (iosize == 0)
	return -EINVAL;

    if (ofs)
	return -EINVAL;

    errno = 0;
    data = strtoll(buf, NULL, 0);
    if (errno != 0) {
	return -errno;
    }

    //XXXX big endian?  data = data << (8 * ((sizeof(data) - varloc->size)));
    memcpy(varloc->addr, &data, varloc->size);
    
    return (ssize_t)iosize;
}

static struct fuse_node_ops fuse_modparm_ops = {
    .read = fuse_modparm_read,
    .write = fuse_modparm_write,
};

fuse_node_t
fuse_modparm_add(const char * name, void * varp, size_t size,
			umode_t mode, struct module * owner)
{
    fuse_node_t parent_fnode;

    assert(size == 1 || size == 2 || size == 4 || size == 8, "%ld", size);

    parent_fnode = fuse_node_lookup("/sys/module");
    if (!parent_fnode)
	return NULL;

    parent_fnode = fuse_node_lookupat(parent_fnode, owner->name);
    if (!parent_fnode)
	return NULL;

    parent_fnode = fuse_node_lookupat(parent_fnode, "parameters");
    if (!parent_fnode)
	return NULL;

    struct varloc * varloc = record_alloc(varloc);
    varloc->addr = varp;
    varloc->size = size;
    varloc->fnode = fuse_node_add(name, parent_fnode, mode,
				    &fuse_modparm_ops, (uintptr_t)varloc);
    if (!varloc->fnode) {
	record_free(varloc);
	return NULL;
    }

    return varloc->fnode;
}

error_t
fuse_modparm_remove(const char * name, struct module * owner)
{
    error_t err;
    struct varloc * varloc;
    uintptr_t varloc_uip;

    fuse_node_t fnode = fuse_node_lookup("/sys/module");
    assert_ne(fnode, 0);

    fnode = fuse_node_lookupat(fnode, owner->name);
    if (!fnode)
	return -ENOENT;
    fnode = fuse_node_lookupat(fnode, "parameters");
    if (!fnode)
	return -ENOENT;

    varloc = (void *)(varloc_uip = fuse_node_data_get(fnode));
    err =  fuse_node_remove(name, fnode);
    if (!err)
	record_free(varloc);

    return err;
}

/******************************************************************************/

static struct task_struct * UMC_FUSE_THREAD;

/* Here starting up and running on the fuse thread */
static int
fuse_thread_run(void * unused)
{
    assert_eq(unused, NULL);
    verify_ne(UMC_FUSE_THREAD, NULL);
    trace_fuse_thread("UMC_fuse thread starts on tid=%u", current->pid);

    error_t err = fuse_loop_run(unused);

    trace_fuse_thread("FUSE thread exits %d", err);
    UMC_FUSE_THREAD = NULL;
    do_exit(err);
}

/* Call once from any thread to start the fuse thread */
error_t
fuse_thread_start(void)
{
    struct task_struct * fuse_thr;
    verify_eq(UMC_FUSE_THREAD, NULL);

    fuse_thr = kthread_create(fuse_thread_run, NULL, "UMC_fuse");
    if (IS_ERR(fuse_thr))
	return PTR_ERR(fuse_thr);

    set_user_nice(fuse_thr, nice(0) - 10);	//XXXX

    kthread_start(fuse_thr);
    return 0;
}

error_t
fuse_thread_stop(void)
{
    /* If we prod the fuse thread it will return from fuse_main() to fuse_loop_run() */
    struct task_struct * fusethread = UMC_FUSE_THREAD;
    if (!fusethread)
	return -EINVAL;

    trace_fuse_thread("tkill %d, SIGTERM", fusethread->pid);
    int rc = tkill(fusethread->pid, SIGTERM);
    expect_eq(rc, 0, "tkill fuse tid=%u errno=%d '%s'",
		     fusethread->pid, errno, strerror(errno));

    /* Wait a second for fuse thread to return to UMC_fuse_run */
    int max = 1000;
    while (UMC_FUSE_THREAD) {
	if (!max--) {
	    pr_warning("UMC_fuse thread didn't exit timely\n");
	    return -EBUSY;
	}
	usleep(1000);
    }

    return 0;
}

/******************************************************************************/

error_t
seq_open(struct file * file, struct seq_operations const * ops)
{
    struct seq_file * seq = record_alloc(seq);
    assert_eq(file->private_data, NULL);
    file->private_data = seq;
    seq->op = ops;
    return 0;
}

error_t
seq_release(struct inode * unused, struct file * file)
{
    struct seq_file * seq_file = file->private_data;
    file->private_data = NULL;
    record_free(seq_file);
    return 0;
}

error_t
single_open(struct file * file, int (*show)(struct seq_file *, void *), void * data)
{
    struct seq_operations *op = record_alloc(op);
    op->show = show;
    error_t err = seq_open(file, op);
    if (err == 0) {
	((struct seq_file *)file->private_data)->priv = data;
    }
    return err;
}

error_t
single_release(struct inode * inode, struct file * file)
{
    const struct seq_operations * op = ((struct seq_file *)file->private_data)->op;
    int rc = seq_release(inode, file);
    record_free((void *)op);
    return rc;
}

/* Return pointer to list position pos from head */
struct list_head *
seq_list_start(struct list_head *head, loff_t pos)
{
    struct list_head *lh;
    list_for_each(lh, head) {
	if (pos-- == 0) {
	    return lh;
	}
    }
    return NULL;	/* not found */
}

/* Return pointer to next position on list from v, or NULL at end of list.
 * Also update the list position index *ppos.
 */
struct list_head *
seq_list_next(void *v, struct list_head *head, loff_t *ppos)
{
    struct list_head *lh;
    lh = ((struct list_head *)v)->next;
    ++*ppos;
    return lh == head ? NULL : lh;
}

/* Use the seq_ops to format and return some state */
void
seq_fmt(struct seq_file * seq)
{
    if (!seq->op->show)
	return;

    if (!seq->op->start) {
	seq->op->show(seq, NULL);
	return;
    }

    loff_t pos = 0;
    void * list_item;

    list_item = seq->op->start(seq, &pos);

    while (list_item) {
	error_t rc = seq->op->show(seq, list_item);
	expect_eq(rc, 0);
	list_item = seq->op->next(seq, list_item, &pos);
    }

    seq->op->stop(seq, list_item);
}

ssize_t
seq_read(struct file * file, void * buf, size_t size, loff_t * lofsp)
{
    struct seq_file * seq = file->private_data;
    assert_ge(*lofsp, 0);

    seq_fmt(seq);   /* generate printable representation */

    size_t reply_size = seq->reply ? strlen(seq->reply) : 0;

    if ((size_t)*lofsp >= reply_size) {
	reply_size = 0;
    } else {
	reply_size -= *lofsp;
    }

    if (reply_size > size)
	reply_size = size;

    if (reply_size) {
	memcpy(buf, seq->reply + *lofsp, reply_size);
	*lofsp += reply_size;
    }

    if (seq->reply) {
	vfree(seq->reply);
	seq->reply = NULL;
    }

    return (ssize_t)reply_size;
}
