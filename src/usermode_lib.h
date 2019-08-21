/* usermode_lib.h
 * Shim for partial emulation/stubbing of Linux kernel functions in usermode
 * Copyright 2015 - 2019 David A. Butterfield
 *
 * This file is not intended to be included from code that was written to run
 * in usermode.
 *
 * This file is automatically included from all the "application code" (kernel
 * code ported to run in usermode) source files.  We include some header files
 * from /usr/include and some header files from the reference kernel.  Some
 * care is required to avoid conflicts.
 */
#ifndef USERMODE_LIB_H
#define USERMODE_LIB_H
#define _GNU_SOURCE

#ifndef __x86_64__
#warning usermode_lib has been compiled on 64-bit x86 only -- work required
#endif

/* Including usermode_lib.h gets you all the UMC headers.
 * You can instead include just a subset if you want.
 */

#include "UMC_sys.h"		/* Basics */
    // #include <sys/types.h>
    // #include <inttypes.h>
    // #include <stdbool.h>
    // #include <limits.h>
    // #include <errno.h>
    // #include <stdlib.h>
    // #include </usr/include/x86_64-linux-gnu/bits/types/struct_iovec.h>
    // #include <string.h>
    // #include <sys_service.h>
    // #include <byteswap.h>
    // #include <endian.h>
    // #include <linux/kernel.h>
    // #include "UMC_kernel.h"
    // #include <linux/list.h>
    // #include <linux/bitmap.h>
    // #include "UMC_assert.h"
    // #include "UMC_time.h"
	// #include <linux/ktime.h>
    // #include "UMC_mem.h"

#include "UMC_thread.h"		/* threads, waiting, locking */
    // #include "UMC_sys.h"
    // #include <pthread.h>
    // #include <signal.h>        // SIGHUP, pthread_kill()
    // #include <errno.h>
    // #include "UMC_lock.h"
	// #include <stddef.h>
	// #include <pthread.h>
	// #include <semaphore.h>
	// #include <valgrind.h>

#include "UMC_bio.h"		/* add block devices and bio */
    // #include "UMC_sys.h"
    // #include "UMC_thread.h"
    // #include "UMC_inode.h"
	// #include "UMC_sys.h"
	// #include "UMC_lock.h"
	// #include <sys/stat.h>
    // #include "UMC_page.h"
	// #include "UMC_sys.h"
	// #include "UMC_lock.h"

#include "UMC_sg.h"		/* scatter/gather */
    // #include "UMC_sys.h"

#include "UMC_file.h"		/* interface to real files */
    // #include "UMC_sys.h"
    // #include "UMC_inode.h"
    // #include "UMC_bio.h"
    // #include <fcntl.h>

#include "UMC_socket.h"		/* interface to real sockets */
    // #include "UMC_sys.h"
    // #include "UMC_file.h"
    // #include "UMC_thread.h"
    // #include <net/checksum.h>
    // #include <linux/skbuff.h>
    // #include <linux/in.h>
    // #include <linux/in6.h>

#include "UMC_netlink.h"	/* netlink simulated using IPv4 */
    // #include "UMC_sys.h"
    // #include "UMC_socket.h"
    // #include <linux/netlink.h>
    // #include <net/genetlink.h>

#include "UMC_fuse_proc.h"	/* /proc simulated using fuse */
    // #include "UMC_sys.h"
    // #include "UMC_file.h"
    // #include "fuse_tree.h"

#include "UMC_stubs.h"	/* referenced by apps but not implemented by UMC */

/* This is an "extra", but it gets initialized from UMC_init() */
void __exit idr_exit_cache(void);
#include <linux/idr.h>

#ifdef INCLUDE_EXTRAS
/* UMC doesn't depend on these, and apps that use them already include them.
 * They are here mainly to ensure they continue to compile successfully.
 */
#include <linux/rbtree.h>
#include <linux/ioctl.h>
#include <linux/swab.h>
#endif

extern error_t UMC_init(const char *);
extern error_t UMC_exit(void);

// XXX KEY:
//	XXX	Not entirely correct, but unlikely to cause trouble unless
//		porting a new application that uses the feature in a new way.
//		E.g. function calls with partially-implemented semantics.
//		(Also, many such conditions are asserted, so there will be
//		notification if some unhandled circumstances arise)
//
//	XXXX	Performance-related --or-- Known incorrect but thought working
//		under current and anticipated usage.
//
//   When you try something new in an application, and it seems like something
//   isn't working right in the system, the ones below might be checked first,
//   because they have already been anticipated to cause trouble:
//
//	XXXXX	Known incorrect, in a way quite possibly affecting anticipated
//		usage.
//
//	XXXXXX	Code is wrong and probably prevents the application from correct
//		operation.

#endif /*  USERMODE_LIB_H */
