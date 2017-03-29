# src/usermode/Makefile
# Copyright 2016 David A. Butterfield
# Makefile for usermode compatibility for Linux kernel source code
# Imports optional MY_SRC, MY_CFLAGS, EXTRA_CFLAGS, CFLAGS, MY_KERNEL

# If the services headers are not in /usr/include, this is where they are
ifdef MY_SRC
MTELIB_H = $(MY_SRC)/include/mtelib.h
EXTRA_CFLAGS +=	-I$(MY_SRC)/include
endif

# EXTRA_CFLAGS += -DDEBUG
# EXTRA_CFLAGS += -DTRACE_TRACE
# EXTRA_CFLAGS += -DTRACE_VERBOSE

EXTRA_CFLAGS += -O3
# EXTRA_CFLAGS += -O2
# EXTRA_CFLAGS += -O1

# disable most of the memory checks remaining when !DEBUG
# EXTRA_CFLAGS += -DOPTIMIZED

# VALGRIND enables small debugging changes; NVALGRIND disables all valgrind checks
# EXTRA_CFLAGS += -DVALGRIND
# EXTRA_CFLAGS += -DNVALGRIND

####################  Enable most compiler warnings  ####################

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
# WFLAGS_WARN += -Wwrite-strings		XXX string initialization problem

## too noisy
# WFLAGS_WARN += -Wpointer-arith
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion

WFLAGS_INHIBIT += -Wno-unused-parameter		# silly

### These are more or less randomly noisy
# WFLAGS_WARN += -Winline
# WFLAGS_WARN += -Wsuggest-attribute=pure
# WFLAGS_WARN += -Wsuggest-attribute=const
# WFLAGS_WARN += -Wsuggest-attribute=noreturn
# WFLAGS_WARN += -Wsuggest-attribute=format
# WFLAGS_WARN += -Wmissing-format-attribute

EXTRA_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT) $(MY_CFLAGS)

#########################################################################

EXTRA_CFLAGS += -isystem kinclude -isystem /usr/include
CFLAGS += -g -fPIC -D_GNU_SOURCE $(EXTRA_CFLAGS)

SRCS_D = usermode_lib.c pde_fuse.c
OBJS_D = $(SRCS_D:.c=.o)

all:	check_kinclude
	$(MAKE) -C . check_include
	$(MAKE) -C . $(OBJS_D)

check_kinclude:
	bash -c "if [[ ! -d kinclude ]] ; then $(MAKE) -C . kinclude; fi"

ifndef MTELIB_H
check_include:
	bash -c "if [[ ! -f /usr/include/mtelib.h ]] ; then $(MAKE) -C . include; fi"
else
check_include:
	bash -c "if [[ ! -f /usr/include/mtelib.h && ! -f $(MTELIB_H) ]] ; then $(MAKE) -C . include; fi"
endif

include:
	echo "***** Install MTE header files into /usr/include or set Makefile MY_SRC to point at MTE/trunk *****" ; exit 1

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

%.o: %.c Makefile
	$(CC) -c -o $@ $(CFLAGS) $<

.depend:
	$(CC) -M $(CFLAGS) $(SRCS_D) > $@

clean:
	rm -f *.o .depend

extraclean: clean
	rm -f *.orig *.rej tags cscope.out
	rm -rf kinclude

#########################################################################

### Create the include directories we use to spoof kernel headers in various ways --
### kinclude tree contains empty files, and symlinks to real kernel header files in UMC subdirectory

### Place to get real kernel header files (need not be current kernel)	    XXX bletch
ifndef MY_KERNEL
# MY_KERNEL = /usr/src/linux-headers-3.13.0-83
# MY_KERNEL = /usr/src/linux-headers-4.4.0-66
MY_KERNEL=`uname -r | sed -e "s/-generic//" -e"s/^/\/usr\/src\/linux-headers-/"`
endif


kinclude:
	### Create empty files so #includes of them successfully do nothing
	/bin/bash -c "mkdir -p kinclude/{asm,asm-generic,net,scsi}"
	/bin/bash -c "touch kinclude/asm/{atomic.h,checksum.h,div64.h,io.h,kmap_types.h,uaccess.h,unaligned.h}"
	/bin/bash -c "touch kinclude/asm-generic/{iomap.h,kmap_types.h,memory_model.h}"
	/bin/bash -c "touch kinclude/net/{sock.h,tcp.h,tcp_states.h}"
	/bin/bash -c "touch kinclude/scsi/{scsi_device.h,scsi_driver.h,scsi_host.h}"
	#
	/bin/bash -c "mkdir -p kinclude/linux"
	/bin/bash -c "touch kinclude/linux/{autoconf.h,bio.h,blkdev.h,bug.h,compiler.h,cpumask.h}"
	/bin/bash -c "touch kinclude/linux/{crc32c.h,crc-t10dif.h,ctype.h,delay.h,dma-mapping.h}"
	/bin/bash -c "touch kinclude/linux/{fcntl.h,file.h,hash.h,init.h,interrupt.h,ip.h,kernel.h}"
	/bin/bash -c "touch kinclude/linux/{kmod.h,kobject.h,kthread.h,ktime.h,lockdep.h,log2.h,mm.h}"
	/bin/bash -c "touch kinclude/linux/{module.h,moduleparam.h,mount.h,mutex.h,namei.h}"
	/bin/bash -c "touch kinclude/linux/{pagemap.h,poison.h,poll.h,proc_fs.h,scatterlist.h}"
	/bin/bash -c "touch kinclude/linux/{seq_file.h,slab.h,spinlock.h,swap.h,syscalls.h,sysfs.h}"
	/bin/bash -c "touch kinclude/linux/{time.h,timer.h,uaccess.h,uio.h,vermagic.h,version.h}"
	/bin/bash -c "touch kinclude/linux/{vmalloc.h,wait.h,workqueue.h,writeback.h}"
	#
	/bin/bash -c "mkdir -p kinclude/rdma"
	/bin/bash -c "touch kinclude/rdma/ib_verbs.h"
	#
	/bin/bash -c "mkdir -p kinclude/linux/{unaligned,byteorder}"
	touch kinclude/linux/byteorder/generic.h
	touch kinclude/linux/unaligned/access_ok.h
	touch kinclude/linux/unaligned/generic.h
	touch kinclude/linux/export.h
	touch kinclude/linux/list.h
	#
	/bin/bash -c "mkdir -p kinclude/scsi"
	touch kinclude/scsi/scsi_proto.h
	touch kinclude/scsi/scsi_common.h
	touch kinclude/scsi/scsi.h
	touch kinclude/scsi/scsi_cmnd.h
	touch kinclude/scsi/scsi_eh.h
	#
	### Create links to a few kernel headers we really do want to include, distinguishing them under UMC name
	/bin/bash -c "mkdir -p kinclude/UMC/linux/{unaligned,byteorder}"
	ln -s $(MY_KERNEL)/include/linux/byteorder/generic.h	kinclude/UMC/linux/byteorder/
	ln -s $(MY_KERNEL)/include/linux/unaligned/access_ok.h	kinclude/UMC/linux/unaligned/
	ln -s $(MY_KERNEL)/include/linux/unaligned/generic.h	kinclude/UMC/linux/unaligned/
	ln -s $(MY_KERNEL)/include/linux/export.h		kinclude/UMC/linux/
	ln -s $(MY_KERNEL)/include/linux/list.h			kinclude/UMC/linux/
	#
	/bin/bash -c "mkdir -p kinclude/UMC/scsi"
	ln -s $(MY_KERNEL)/include/scsi/scsi.h			kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_cmnd.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_eh.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_proto.h		kinclude/UMC/scsi/
	ln -s $(MY_KERNEL)/include/scsi/scsi_common.h		kinclude/UMC/scsi/
