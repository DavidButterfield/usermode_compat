# UMC/trunk/src/Makefile
# Makefile for usermode compatibility for Linux kernel source code
# Imports optional SYS_SERVICE_INCL, CFLAGS, MY_KERNEL

MY_KERNEL=/home/dave/git/linux-2.6.32.27

MY_CFLAGS += -DDEBUG
MY_CFLAGS += -fsanitize=undefined
# MY_CFLAGS += -DNDEBUG
# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE

# MY_CFLAGS += -Og
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2
# MY_CFLAGS += -O3

# disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables memory initialization; NVALGRIND disables all valgrind checks
# MY_CFLAGS += -DVALGRIND
# MY_CFLAGS += -DNVALGRIND

### Place to get mtelib.h and sys_service.h (et. al.), if not in /usr/include
SYS_SERVICE_INCL=../../MTE/include

MY_CFLAGS += -I$(SYS_SERVICE_INCL)
MTELIB_H := $(SYS_SERVICE_INCL)/mtelib.h

### Place to get real kernel header files (does not have to be the current kernel)
ifndef MY_KERNEL
export MY_KERNEL := /usr/src/linux-headers-$(shell uname -r | sed -e s/-generic//)
endif

########################  Enable most compiler warnings  #######################

WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wundef
WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wredundant-decls
WFLAGS_WARN += -Wbad-function-cast
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wunsafe-loop-optimizations
WFLAGS_WARN += -Wcast-qual
WFLAGS_WARN += -Wformat=2
WFLAGS_WARN += -Wshadow
WFLAGS_WARN += -Wswitch-default
WFLAGS_WARN += -Wswitch-enum
# WFLAGS_WARN += -Wwrite-strings

## too noisy
# WFLAGS_WARN += -Wpointer-arith
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion

# silly
WFLAGS_INHIBIT += -Wno-unused-parameter

MY_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

################################################################################
SHELL=/bin/bash

MY_CFLAGS += -g -fPIC -fno-omit-frame-pointer -D_GNU_SOURCE -I. -Ikinclude -Ikinclude/UMC

SRCS_D = usermode_lib.c UMC_fuse.c UMC_genl.c
OBJS_D = $(SRCS_D:.c=.o)

all:	check_kinclude check_include cscope
	$(MAKE) .depend
	$(MAKE) $(OBJS_D)

drbd:	all

scst:	all

check_kinclude:
	@if [[ ! -d kinclude ]] ; then $(MAKE) kinclude; fi

ifndef MTELIB_H
check_include:	check_kinclude
	@if [[ ! -f /usr/include/mtelib.h ]] ; then $(MAKE) include; fi
else
check_include:	check_kinclude
	@if [[ ! -f /usr/include/mtelib.h && ! -f $(MTELIB_H) ]] ; then $(MAKE) include; fi
endif

include:
	@echo "***** Install MTE header files into /usr/include or set Makefile SYS_SERVICE_INCL to point at MTE/trunk/include *****" ; exit 1

%.o: %.c Makefile | check_kinclude check_include
	$(CC) -c -o $@ $(CFLAGS) $(MY_CFLAGS) $<

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

.depend:
	$(CC) -M $(CFLAGS) $(MY_CFLAGS) $(SRCS_D) > $@

clean:
	rm -f *.o .depend

extraclean: clean
	rm -f *.orig *.rej tags cscope.out
	rm -rf kinclude

cscope:
	@cscope -b -c -R
	@ctags        -R

.PHONY:	all include check_include check_kinclude cscope kinclude

#########################################################################

### Create the include directories we use to spoof kernel headers in various ways --
### kinclude tree contains empty files, and symlinks to real kernel header files in UMC subdirectory

kinclude:   kinclude_links kinclude_empty kinclude_empty2

kinclude_links:
	@### Create links to a few kernel headers we really do want to include.
	@### Give them /UMC/ names so they are only included explicitly;
	@### without the UMC name the dummy empty header file gets included.
	@mkdir -p kinclude/UMC/linux/unaligned
	@mkdir -p kinclude/UMC/linux/byteorder
	@ln -s $(MY_KERNEL)/include/linux/unaligned/generic.h	kinclude/UMC/linux/unaligned/
	@ln -s $(MY_KERNEL)/include/linux/byteorder/generic.h	kinclude/UMC/linux/byteorder/
	@ln -s $(MY_KERNEL)/include/linux/unaligned/access_ok.h	kinclude/UMC/linux/unaligned/
	@ln -s $(MY_KERNEL)/include/linux/list.h		kinclude/UMC/linux/
	@#
	@ln -s $(MY_KERNEL)/include/linux/typecheck.h		kinclude/UMC/linux/
	@ln -s $(MY_KERNEL)/include/linux/rbtree.h		kinclude/UMC/linux/
	@ln -s $(MY_KERNEL)/include/linux/genetlink.h		kinclude/UMC/linux/
	@#
	@mkdir -p kinclude/UMC/scsi
	@ln -s $(MY_KERNEL)/include/scsi/scsi.h			kinclude/UMC/scsi/
	@ln -s $(MY_KERNEL)/include/scsi/scsi_cmnd.h		kinclude/UMC/scsi/
	@ln -s $(MY_KERNEL)/include/scsi/scsi_eh.h		kinclude/UMC/scsi/
	@#
	@mkdir -p kinclude/UMC/arch/x86/include/asm
	@ln -s $(MY_KERNEL)/arch/x86/include/asm/cmpxchg.h	kinclude/UMC/arch/x86/include/asm/
	@#
	@mkdir -p kinclude/UMC/net
	@ln -s $(MY_KERNEL)/include/net/genetlink.h		kinclude/UMC/net

kinclude_empty2:
	@### Create empty files so #includes of them successfully do nothing
	@### These get #included by the SCST kernel files when compiling for SCST_USERMODE
	@### These correspond to the /UMC/ names linked above
	@mkdir -p kinclude/linux/unaligned
	@mkdir -p kinclude/linux/byteorder
	@touch kinclude/linux/byteorder/generic.h
	@touch kinclude/linux/list.h
	@touch kinclude/linux/unaligned/access_ok.h
	@touch kinclude/linux/unaligned/generic.h
	@#
	@touch kinclude/linux/typecheck.h
	@touch kinclude/linux/rbtree.h
	@touch kinclude/linux/genetlink.h
	@#
	@mkdir -p kinclude/scsi
	@touch kinclude/scsi/scsi_cmnd.h
	@touch kinclude/scsi/scsi_eh.h
	@touch kinclude/scsi/scsi.h
	@#
	@mkdir -p kinclude/arch/x86/include/asm
	@touch kinclude/arch/x86/include/asm/cmpxchg.h
	@#
	@#
	@mkdir -p kinclude/net
	@touch kinclude/net/genetlink.h

kinclude_empty:
	@### Create empty files so #includes of them successfully do nothing
	@### These get #included by the SCST kernel files when compiling for SCST_USERMODE
	@mkdir -p kinclude/asm
	@touch kinclude/asm/alternative.h
	@touch kinclude/asm/atomic.h
	@touch kinclude/asm/checksum.h
	@touch kinclude/asm/cmpxchg_64.h
	@touch kinclude/asm/cpufeatures.h
	@touch kinclude/asm/div64.h
	@touch kinclude/asm/io.h
	@touch kinclude/asm/kmap_types.h
	@touch kinclude/asm/param.h
	@touch kinclude/asm/semaphore.h
	@touch kinclude/asm/system.h
	@touch kinclude/asm/uaccess.h
	@touch kinclude/asm/unaligned.h
	@#
	@mkdir -p kinclude/asm-generic
	@touch kinclude/asm-generic/iomap.h
	@touch kinclude/asm-generic/kmap_types.h
	@touch kinclude/asm-generic/memory_model.h
	@#
	@mkdir -p kinclude/uapi/linux/sched/
	@touch kinclude/uapi/linux/sched/types.h
	@#
	@mkdir -p kinclude/linux/sched/
	@touch kinclude/linux/sched/signal.h
	@#
	@mkdir -p kinclude/net
	@touch kinclude/net/ipv6.h
	@touch kinclude/net/netlink.h
	@touch kinclude/net/net_namespace.h
	@touch kinclude/net/sock.h
	@touch kinclude/net/tcp.h
	@touch kinclude/net/tcp_states.h
	@#
	@mkdir -p kinclude/crypto
	@touch kinclude/crypto/hash.h
	@#
	@mkdir -p kinclude/scsi
	@touch kinclude/scsi/scsi_device.h
	@touch kinclude/scsi/scsi_driver.h
	@touch kinclude/scsi/scsi_host.h
	@#
	@mkdir -p kinclude/rdma
	@touch kinclude/rdma/ib_verbs.h
	@touch kinclude/rdma/ib_cache.h
	@#
	@mkdir -p kinclude/linux
	@touch kinclude/linux/{autoconf.h,bio.h,blkdev.h,bug.h,compiler.h,cpumask.h}
	@touch kinclude/linux/{crc32c.h,crc-t10dif.h,ctype.h,delay.h,dma-mapping.h}
	@touch kinclude/linux/{fcntl.h,file.h,hash.h,init.h,interrupt.h,ip.h,kernel.h}
	@touch kinclude/linux/{kmod.h,kobject.h,kthread.h,ktime.h,lockdep.h,log2.h,mm.h}
	@touch kinclude/linux/{module.h,moduleparam.h,mount.h,mutex.h,namei.h}
	@touch kinclude/linux/{pagemap.h,poison.h,poll.h,proc_fs.h,scatterlist.h}
	@touch kinclude/linux/{seq_file.h,slab.h,spinlock.h,swap.h,syscalls.h,sysfs.h}
	@touch kinclude/linux/{time.h,timer.h,uaccess.h,uio.h,vermagic.h,version.h}
	@touch kinclude/linux/{vmalloc.h,wait.h,workqueue.h,writeback.h}
	@#
	@touch kinclude/linux/atomic.h
	@touch kinclude/linux/backing-dev.h
	@touch kinclude/linux/bitops.h
	@touch kinclude/linux/blk-mq.h
	@touch kinclude/linux/blkpg.h
	@touch kinclude/linux/completion.h
	@touch kinclude/linux/crypto.h
	@touch kinclude/linux/dcache.h
	@touch kinclude/linux/debugfs.h
	@touch kinclude/linux/device.h
	@touch kinclude/linux/dynamic_debug.h
	@touch kinclude/linux/err.h
	@touch kinclude/linux/file.h
	@touch kinclude/linux/fs.h
	@touch kinclude/linux/genhd.h
	@touch kinclude/linux/genl_magic_func.h
	@touch kinclude/linux/highmem.h
	@touch kinclude/linux/idr.h
	@touch kinclude/linux/jiffies.h
	@touch kinclude/linux/kref.h
	@touch kinclude/linux/lru_cache.h
	@touch kinclude/linux/major.h
	@touch kinclude/linux/memcontrol.h
	@touch kinclude/linux/mm_inline.h
	@touch kinclude/linux/net.h
	@touch kinclude/linux/netlink.h
	@touch kinclude/linux/notifier.h
	@touch kinclude/linux/once.h
	@touch kinclude/linux/prefetch.h
	@touch kinclude/linux/random.h
	@touch kinclude/linux/ratelimit.h
	@touch kinclude/linux/rcupdate.h
	@touch kinclude/linux/reboot.h
	@touch kinclude/linux/sched.h
	@touch kinclude/linux/security.h
	@touch kinclude/linux/stat.h
	@touch kinclude/linux/string.h
	@touch kinclude/linux/stringify.h
	@touch kinclude/linux/tcp.h
	@#
	@touch kinclude/kref_debug.h

do_not_touch:
	@# XXX We currently seem to get these from /usr/include
	@# XXX This isn't right!
	@#touch kinclude/asm/byteorder.h
	@#touch kinclude/asm/types.h
	@#touch kinclude/linux/errno.h
	@#touch kinclude/linux/in.h
	@#touch kinclude/linux/pkt_sched.h
	@#touch kinclude/linux/socket.h
	@#touch kinclude/linux/swab.h
	@#touch kinclude/linux/types.h
	@#touch kinclude/linux/unistd.h
