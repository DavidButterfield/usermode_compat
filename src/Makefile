# UMC/trunk/src/Makefile
# Makefile for usermode compatibility for Linux kernel source code
# Imports optional SYS_SERVICE_INCL, CFLAGS, MY_KERNEL

MY_CFLAGS += -DDEBUG
MY_CFLAGS += -fsanitize=undefined
# MY_CFLAGS += -DNDEBUG
# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE

# MY_CFLAGS += -Og
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2
# MY_CFLAGS += -O3 -fno-strict-aliasing
# MY_CFLAGS += -O3

# disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables memory initialization; NVALGRIND disables all valgrind checks
# MY_CFLAGS += -DVALGRIND
# MY_CFLAGS += -DNVALGRIND

### Place to get mtelib.h and sys_service.h (et. al.), if not in /usr/include
ifndef SYS_SERVICE_INCL
# This only matters if headers are not in /usr/include: Assumes MTE/trunk and
# UMC/trunk are under the same directory.  Otherwise pass in SYS_SERVICE_INCL.
SYS_SERVICE_INCL=../../../MTE/trunk/include
endif

ifdef SYS_SERVICE_INCL
MY_CFLAGS += -I$(SYS_SERVICE_INCL)
MTELIB_H := $(SYS_SERVICE_INCL)/mtelib.h
endif

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

MY_CFLAGS += -g -fPIC -D_GNU_SOURCE -I. -Ikinclude -Ikinclude/UMC

SRCS_D = usermode_lib.c pde_fuse.c
OBJS_D = $(SRCS_D:.c=.o)

all:	check_kinclude check_include
	$(MAKE) $(OBJS_D)

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
	$(CC) -M $(CFLAGS) $(SRCS_D) > $@

clean:
	rm -f *.o .depend

extraclean: clean
	rm -f *.orig *.rej tags cscope.out
	rm -rf kinclude

.PHONY:	all include check_include check_kinclude	

#########################################################################

### Create the include directories we use to spoof kernel headers in various ways --
### kinclude tree contains empty files, and symlinks to real kernel header files in UMC subdirectory

kinclude:
	### Create empty files so #includes of them successfully do nothing
	### These get #included by the SCST kernel files when compiling for SCST_USERMODE
	mkdir -p kinclude/{asm,asm-generic,net,scsi}
	@touch kinclude/asm/{atomic.h,checksum.h,div64.h,io.h,kmap_types.h,uaccess.h,unaligned.h}
	@touch kinclude/asm-generic/{iomap.h,kmap_types.h,memory_model.h}
	@touch kinclude/net/{sock.h,tcp.h,tcp_states.h}
	@touch kinclude/scsi/{scsi_device.h,scsi_driver.h,scsi_host.h}
	@#
	mkdir -p kinclude/linux
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
	mkdir -p kinclude/rdma
	@touch kinclude/rdma/ib_verbs.h
	@#
	### These correspond to the /UMC/ names linked below
	mkdir -p kinclude/linux/{unaligned,byteorder}
	@touch kinclude/linux/byteorder/generic.h
	@touch kinclude/linux/unaligned/access_ok.h
	@touch kinclude/linux/unaligned/generic.h
	@touch kinclude/linux/export.h
	@touch kinclude/linux/list.h
	@#
	mkdir -p kinclude/scsi
	@touch kinclude/scsi/scsi_proto.h
	@touch kinclude/scsi/scsi_common.h
	@touch kinclude/scsi/scsi.h
	@touch kinclude/scsi/scsi_cmnd.h
	@touch kinclude/scsi/scsi_eh.h
	@#
	### Create links to a few kernel headers we really do want to include.
	### Give them /UMC/ names so they are only included explicitly;
	### without the UMC name the dummy empty header file gets included.
	###
	### These are only included from usermode_lib.h
	mkdir -p kinclude/UMC/linux/{unaligned,byteorder}
	mkdir -p kinclude/UMC/uapi/linux/byteorder
	ln -s $(MY_KERNEL)/include/uapi/linux/byteorder/little_endian.h kinclude/UMC/uapi/linux/byteorder/
	ln -s $(MY_KERNEL)/include/linux/byteorder/generic.h	kinclude/UMC/linux/byteorder/
	ln -s $(MY_KERNEL)/include/linux/unaligned/access_ok.h	kinclude/UMC/linux/unaligned/
	ln -s $(MY_KERNEL)/include/linux/unaligned/generic.h	kinclude/UMC/linux/unaligned/
	ln -s $(MY_KERNEL)/include/linux/export.h		kinclude/UMC/linux/
	ln -s $(MY_KERNEL)/include/linux/list.h			kinclude/UMC/linux/
	#
	### These are only included from scst_compat.h
	mkdir -p kinclude/UMC/scsi
	ln -s $(MY_KERNEL)/include/scsi/scsi.h			kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_cmnd.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_eh.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_proto.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_common.h		kinclude/UMC/scsi/

