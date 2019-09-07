/* UMC_fuse_proc.h -- usermode compatibility for /proc using fuse
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_FUSE_PROC_H
#define UMC_FUSE_PROC_H
#include "UMC_sys.h"
#include "fuse_tree.h"
#include "UMC_file.h"

/* Start/control the FUSE thread */
extern error_t fuse_thread_start(void);
extern error_t fuse_thread_stop(void);

#define seq_lseek			NULL	/* unused */

struct seq_file {
    struct seq_operations const   * op;		/* start, show, next, stop */
    union {
	void			  * private;	/* 2.6.24 */
	void			  * priv;	/* 2.6.26 */
    };
    char *			    reply;	/* accumulates seq_printfs */
};

struct seq_operations {
    void		      * (*start)(struct seq_file *, loff_t * pos);
    void		      * (*next)(struct seq_file *, void *, loff_t * pos);
    void			(*stop)(struct seq_file *, void *);
    int				(*show)(struct seq_file *, void *);
};

/* Format into a string and append to seq->reply */
#define seq_printf(seq, fmtargs...) \
    ((seq)->reply = UMC_string_concat_free((seq)->reply, kasprintf(0, ""fmtargs)))

static inline error_t
seq_putc(struct seq_file * seq, char c)
{
    seq_printf(seq, "%c", c);
    return 0;
}

static inline error_t
seq_puts(struct seq_file * seq, char * s)
{
    seq_printf(seq, "%s", s);
    return 0;
}

extern error_t seq_open(struct file * file, struct seq_operations const * ops);
extern error_t seq_release(struct inode * unused, struct file * file);
extern error_t single_open(struct file * file, int (*show)(struct seq_file *, void *), void * data);
extern error_t single_release(struct inode * inode, struct file * file);
extern struct list_head * seq_list_start(struct list_head *head, loff_t pos);
extern struct list_head * seq_list_next(void *v, struct list_head *head, loff_t *ppos);
extern void seq_fmt(struct seq_file * seq);
extern ssize_t seq_read(struct file * file, void * buf, size_t size, loff_t * lofsp);

/******************************************************************************/

/* Map fuse_tree_op to /proc file_operations */
#define proc_dir_entry fuse_node

/* NULL parent refers to the /proc node */
extern struct proc_dir_entry * fuse_pde_add(const char * name,
		struct proc_dir_entry * parent, umode_t mode,
		const struct file_operations * fops, void * data);

extern struct proc_dir_entry *
fuse_pde_mkdir(const char * name, struct proc_dir_entry * parent);

extern error_t fuse_pde_remove(const char * name, struct proc_dir_entry * parent);

#define proc_create_data(name, mode, parent, fops, data) \
		fuse_pde_add((name), (parent), (mode), (fops), (data))

#define proc_create(name, mode, parent, fops) \
		proc_create_data((name), (mode), (parent), (fops), NULL)

#define create_proc_entry(name, mode, parent) \
		proc_create_data((name), (mode), (parent), NULL, NULL)

#define proc_mkdir(name, parent) fuse_pde_mkdir((name), (parent))

#define remove_proc_entry(name, parent) fuse_pde_remove((name), (parent))

/* NULL parent refers to the /dev node */
extern struct proc_dir_entry * fuse_dev_add(const char * name,
		struct proc_dir_entry * parent, umode_t mode,
		const struct file_operations * fops, void * data);

extern struct proc_dir_entry *
fuse_dev_mkdir(const char * name, struct proc_dir_entry * parent);

extern error_t fuse_dev_remove(const char * name, struct proc_dir_entry * parent);

/******************************************************************************/

extern struct proc_dir_entry * fuse_module_mkdir(struct module *);
extern error_t fuse_module_rmdir(struct module *);

/* These are for accessing "module_param_named" variables */
extern fuse_node_t fuse_modparm_add(const char *, void *, size_t, umode_t, struct module *);
extern error_t fuse_modparm_remove(const char * name, struct module *);

/* Each instance in the source of module_param_named() here defines two functions to add and
 * remove a reference to the named variable in the PDE tree.  The functions are called from
 * the application compatibility init and exit functions.
 */
//XXX use the vartype, which denotes the names of check functions
#define module_param_named(procname, varname, vartype, modeperms) \
 extern void _CONCAT(fuse_modparm_add_, procname)(void); \
	void _CONCAT(fuse_modparm_add_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    fuse_modparm_add(#procname, &varname, sizeof(varname), \
				    (modeperms), THIS_MODULE); \
	} \
 \
 extern void _CONCAT(fuse_modparm_remove_, procname)(void); \
	void _CONCAT(fuse_modparm_remove_, procname)(void)  \
	{ \
	    assert_eq(sizeof(vartype), sizeof(varname)); \
	    fuse_modparm_remove(#procname, THIS_MODULE); \
	}

#define module_param(var, type, mode)	module_param_named(var, var, type, (mode))

/******************************************************************************/

/* SCST utters PROC_I(inode)->pde->data */
#define PROC_I(inode)	({ assert_eq((inode)->UMC_type, I_TYPE_PROC); (inode); })

#define inode_pde(inode)		((inode)->pde)
#define PDE(inode)			inode_pde(inode)

#endif /* UMC_FUSE_PROC_H */
