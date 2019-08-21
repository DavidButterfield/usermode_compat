/* usermode_lib.c
 * Compatibility for kernel code running in usermode
 * Copyright 2016-2019 David A. Butterfield
 */
#define _GNU_SOURCE
#include "usermode_lib.h"
#include "fuse_tree.h"
#include "libtcmur.h"
#include "UMC_fuse_proc.h"
#include <ctype.h>

/* Initialize the usermode_lib usermode compatibility module */
/* mountpoint is the path to the procfs or sysfs mount point */
error_t
UMC_init(const char * mountpoint)
{
    sys_tz.tz_minuteswest = (int)(timezone/60);	/* see tzset(3) */
    sys_tz.tz_dsttime = daylight;		/* see tzset(3) */

    idr_init_cache();

    /* Set up "current" for this initial thread */
    assert_eq(current, NULL);
    UMC_current_init(&UMC_init_current_space, sys_thread_current(),
		 (void *)UMC_init, NULL, sys_thread_name(sys_thread_current()));
    UMC_current_set(&UMC_init_current_space);

    {
	cpu_set_t mask;
	sched_getaffinity(current->pid/*tid*/, sizeof(mask), &mask);
	nr_cpu_ids = CPU_COUNT(&mask);
    }

    UMC_sig_setup();

    /* Initialize a page of zeros for general use */
    {
	struct page * page = &zero_page;
	kref_init(&page->kref);
	mutex_init(&page->lock);
	page->order = 0;	/* single page */
	page_address(page) = empty_zero_page;
	//XXX is this really supposed to be on UMC_page_list?
	spin_lock(&UMC_pagelist_lock);
	list_add(&page->UMC_page_list, &UMC_pagelist);
	spin_unlock(&UMC_pagelist_lock);
    }

    /* Threads */

    /* fuse forks, so start it before anything that opens file descriptors */
    {
	error_t err;
	int tcmur_major = 0;			//XXXX
	int tcmur_max_minor = 256;		//XXXX

	err = libtcmur_init(NULL);		/* default handler_prefix */
	verify_eq(err, 0, "libtcmur_init");

	UMC_fuse_mount_point = mountpoint;
	err = fuse_tree_init(mountpoint);
	verify_eq(err, 0, "fuse_tree_init");

	fuse_tree_mkdir("proc", NULL);
	fuse_tree_mkdir("dev", NULL);
	fuse_node_t fnode_sys = fuse_tree_mkdir("sys", NULL);
	fuse_tree_mkdir("module", fnode_sys);

	/* bio_tcmur_init() after /dev established */
	err = bio_tcmur_init(tcmur_major, tcmur_max_minor);
	verify_eq(err, 0, "bio_tcmur_init");

	err = fuse_bio_init();
	verify_eq(err, 0, "fuse_bio_init");

	err = fuse_thread_start();
	verify_eq(err, 0, "fuse_thread_start");
    }

    /* Start the RCU callback thread */
    UMC_rcu_cb_thr = kthread_run(UMC_rcu_cb_fn, NULL, "%s", "RCU_callback");

    /* Start the general-purpose event thread */
    {
	struct sys_event_task_cfg cfg = {
	    .max_polls = SYS_ETASK_MAX_POLLS,
	    .max_steps = SYS_ETASK_MAX_STEPS,
	};
	UMC_irqthread = irqthread_run(&cfg, "UMC_irqthread");
    }

    /* Start the general-purpose work queue */
    UMC_workq = create_workqueue("UMC_workq");

    /* Start the netlink listener */
    netlink_init();

    return 0;
}

error_t
UMC_exit(void)
{
    error_t err;
    assert(current);

    netlink_exit();

    irqthread_stop(UMC_irqthread);
    UMC_irqthread = NULL;

    {
	err = fuse_thread_stop();
	if (err == -EINVAL)
	    { /* fuse thread already gone -- ignore the EINVAL */ }
	else {
	    expect_eq(err, 0, "fuse_thread_stop");
	}

	if (!err) {
	    err = fuse_bio_exit();
	    expect_eq(err, 0, "fuse_bio_exit");

	    err = bio_tcmur_exit();
	    expect_eq(err, 0, "bio_tcmur_exit");

	    fuse_tree_rmdir("proc", NULL);
	    fuse_tree_rmdir("dev", NULL);
	    fuse_node_t fnode_sys = fuse_node_lookup("sys");
	    fuse_tree_rmdir("module", fnode_sys);
	    fuse_tree_rmdir("sys", NULL);

	    err = fuse_tree_exit();
	    expect_eq(err, 0, "fuse_tree_exit");

	    err = libtcmur_exit();
	    expect_eq(err, 0, "libtcmur_exit");
	}
    }

    flush_workqueue(UMC_workq);
    destroy_workqueue(UMC_workq);
    UMC_workq = NULL;

    kthread_stop(UMC_rcu_cb_thr);

    libtcmur_exit();
    idr_exit_cache();

    return err;
}

/* Import source from the reference kernel */
//XXX compile separately?
#include "klib/dec_and_lock.c"
#include "klib/bitmap.c"
#include "klib/idr.c"
#include "klib/nlattr.c"
#include "klib/rbtree.c"

/******************************************************************************/

/* UMC depends on these symbols in addition to the ones defined in sys_service.h
 * 
 * errno strerror
 * daylight timezone
 * memchr memcmp memcpy memset
 * strcmp strlen strncmp strncpy strtol strtoll strtoul strtoull toupper
 *
 * fflush fileno fprintf snprintf stderr
 * close open
 * 
 * accept4 bind connect getpeername getsockname listen recvfrom recvmsg
 * send sendmsg sendto setsockopt shutdown socket socketpair
 * 
 * nice sched_getaffinity setpriority
 * usleep
 * sigaction
 * syscall.gettid syscall.tkill
 *
 * sysinfo; or si_meminfo->totalram
 * fork, execve, exit, and waitpid; or call_usermodehelper(progpath, argv[], envp[], waitflag)
 * 
 * pthread_self pthread_kill
 * pthread_condattr_destroy pthread_condattr_init pthread_condattr_setclock
 * pthread_cond_broadcast pthread_cond_init pthread_cond_signal pthread_cond_timedwait
 * pthread_mutex_destroy pthread_mutex_lock pthread_mutex_timedlock pthread_mutex_trylock pthread_mutex_unlock
 */
