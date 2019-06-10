# usermode_compat/src/Makefile
# Makefile for usermode compatibility for Linux kernel source code
# Imports optional SYS_SERVICE_INCL, CFLAGS, REF_KERNEL

ifndef REF_KERNEL
### Place to get real kernel header files (preferably of the level being emulated)
# REF_KERNEL := /usr/src/linux-headers-$(shell uname -r | sed -e s/-generic//)
REF_KERNEL := $(shell /bin/pwd)/../../linux-2.6.32.27
endif

MY_CFLAGS += -DDEBUG
# MY_CFLAGS += -fsanitize=undefined
# MY_CFLAGS += -DNDEBUG
# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE

MY_CFLAGS += -O0
# MY_CFLAGS += -Og
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2
# MY_CFLAGS += -O3

# disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables memory initialization; NVALGRIND disables all valgrind checks
# MY_CFLAGS += -DVALGRIND
# MY_CFLAGS += -DNVALGRIND

ifndef SYS_SERVICE_INCL
### Place to get mtelib.h and sys_service.h (et. al.), if not in /usr/include
SYS_SERVICE_INCL=../../MTE/include
endif

MY_CFLAGS += -I$(SYS_SERVICE_INCL)
MTELIB_H := $(SYS_SERVICE_INCL)/mtelib.h

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
WFLAGS_WARN += -Wformat=2
WFLAGS_WARN += -Wshadow
WFLAGS_WARN += -Wswitch-default
WFLAGS_WARN += -Wswitch-enum
WFLAGS_WARN += -Wfloat-conversion
WFLAGS_WARN += -fstrict-aliasing -Wstrict-aliasing
# WFLAGS_WARN += -Wcast-qual		# 2 in kernel genetlink.h
# WFLAGS_WARN += -Wwrite-strings

## too noisy
# WFLAGS_WARN += -Wpointer-arith
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion

WFLAGS_INHIBIT += -Wno-sign-compare	# some kernel code

# silly
WFLAGS_INHIBIT += -Wno-unused-parameter

MY_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

################################################################################
SHELL=/bin/bash

MY_CFLAGS += -g -ggdb -fno-omit-frame-pointer -D_GNU_SOURCE -fPIC -I. -isystem ./arch/x86/include -isystem include

SRCS_D = usermode_lib.c UMC_fuse.c
OBJS_D = $(SRCS_D:.c=.o)

all:	check_include check_MTE
	$(MAKE) cscope
	$(MAKE) .depend
	$(MAKE) $(OBJS_D)

check_include:
	@if [[ ! -d include ]] ; then $(MAKE) include; fi

ifndef MTELIB_H
check_MTE:
	@if [[ ! -f /usr/include/mtelib.h ]] ; then $(MAKE) include; fi
else
check_MTE:
	@if [[ ! -f /usr/include/mtelib.h && ! -f $(MTELIB_H) ]] ; then $(MAKE) install; fi
endif

install:
	@echo "***** Manually copy MTE header files into /usr/include or set Makefile SYS_SERVICE_INCL to point at MTE/trunk/include *****" ; exit 1

%.o: %.c Makefile | check_include check_MTE
	$(CC) -c -o $@ $(CFLAGS) $(MY_CFLAGS) $<

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

.depend:
	$(CC) -M $(CFLAGS) $(MY_CFLAGS) $(SRCS_D) > $@

clean:
	rm -f *.o .depend
	rm -f tags cscope.out

extraclean: clean
	rm -f *.orig *.rej
	rm -rf include arch

cscope:
	@cscope -b -c -R
	@ctags        -R

.PHONY:	all include check_MTE check_include cscope

#########################################################################

# Create a mostly-empty copy of the include and arch subdirectories of $(REF_KERNEL).
# First build an empty tree, then copy in the files we need.
# The empty tree provides non-failing, but empty, targets for #include directives.
# Usermode build uses the actual kernel headers copied below.

DIR := $(shell /bin/pwd)

include:   _include
	@echo Modified header files:
	cp kincl_mod/netlink.h	    include/net/
	cp kincl_mod/kernel.h	    include/linux/
	cp kincl_mod/types.h	    include/linux/
	touch			    include/linux/version.h
	touch			    include/linux/export.h
	touch			    include/linux/autoconf.h

_include:
	@echo Copy selected kernel header files for inclusion by apps building for usermode
	@(cd $(REF_KERNEL)/arch; for d in `find x86   -type d`   ; do mkdir -p  $(DIR)/arch/$$d ; done)
	@(cd $(REF_KERNEL)/arch; for f in `find x86 ! -type d,l` ; do touch     $(DIR)/arch/$$f ; done)
	@(cd $(REF_KERNEL)/arch; for l in `find x86   -type l`   ; do cp -d $$l $(DIR)/arch/$$l ; done)
	@
	@(cd $(REF_KERNEL)/include; for d in `find   -type d`   ; do mkdir -p  $(DIR)/include/$$d ; done)
	@(cd $(REF_KERNEL)/include; for f in `find ! -type d,l` ; do touch     $(DIR)/include/$$f ; done)
	@(cd $(REF_KERNEL)/include; for l in `find   -type l`   ; do cp -d $$l $(DIR)/include/$$l ; done)
	@
	@
	@ cp $(REF_KERNEL)/include/linux/byteorder/*.h		include/linux/byteorder/
	@ cp $(REF_KERNEL)/include/linux/unaligned/*.h		include/linux/unaligned/
	@
	@ cp $(REF_KERNEL)/include/linux/kernel.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/prefetch.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/linux/typecheck.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/poison.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/linux/bitmap.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/bitops.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/bitrev.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/cpumask.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/ctype.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/idr.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/jiffies.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/kobject.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/kref.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/ktime.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/list.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/log2.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/parser.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/plist.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/prio_heap.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/prio_tree.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/proportions.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/radix-tree.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/ratelimit.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rational.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/rbtree.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/reciprocal_div.h	include/linux/
	@#cp $(REF_KERNEL)/include/linux/sort.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/uio.h			include/linux/
	@
	@#cp $(REF_KERNEL)/include/linux/blkdev.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem-spinlock.h	include/linux/
	@#cp $(REF_KERNEL)/include/linux/string.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/time.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/timer.h		include/linux/
	@
	@#cp $(REF_KERNEL)/include/linux/crc16.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc32.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc7.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc-ccitt.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc-itu-t.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc-t10dif.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/linux/inet.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/in.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/in6.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/net.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/skbuff.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/tcp.h			include/linux/
	@
	@ cp $(REF_KERNEL)/include/linux/genetlink.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/netlink.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/net/genetlink.h		include/net/
	@ cp $(REF_KERNEL)/include/net/netlink.h		include/net/
	@
	@#cp $(REF_KERNEL)/include/config/libcrc32c.h		include/config/
	@#cp $(REF_KERNEL)/include/config/nlattr.h		include/config/
	@#cp $(REF_KERNEL)/include/config/crypto/sha1.h		include/config/
	@
	@ cp $(REF_KERNEL)/include/scsi/scsi_cmnd.h		include/scsi/
	@ cp $(REF_KERNEL)/include/scsi/scsi_eh.h		include/scsi/
	@ cp $(REF_KERNEL)/include/scsi/scsi.h			include/scsi/
	@
	@
	@#cp $(REF_KERNEL)/include/linux/kmemcheck.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/spinlock.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/thread_info.h		include/linux/
	@
	@ cp $(REF_KERNEL)/arch/x86/include/asm/kmemcheck.h	arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/rwsem.h		arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/spinlock.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/thread_info.h	arch/x86/include/asm/
	@
	@
	@#cp $(REF_KERNEL)/include/linux/bitops.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/bug.h			include/linux/
	@ cp $(REF_KERNEL)/include/net/checksum.h		include/net/
	@ cp $(REF_KERNEL)/include/linux/errno.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/fcntl.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/ioctl.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/linkage.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/posix_types.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/scatterlist.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/socket.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/sockios.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/swab.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/types.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/unistd.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/asm-generic/bitops.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/bug.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/checksum.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/errno.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/fcntl.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/ioctl.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/linkage.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/posix_types.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/scatterlist.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/socket.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/sockios.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/swab.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/types.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/unistd.h		include/asm-generic/
	@
	@ cp $(REF_KERNEL)/arch/x86/include/asm/bitops.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/bug.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/checksum.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/errno.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/fcntl.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/ioctl.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/linkage.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/posix_types.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/scatterlist.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/socket.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/sockios.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/swab.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/types.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unistd.h	arch/x86/include/asm/
	@
	@
	@#cp $(REF_KERNEL)/include/asm-generic/atomic-long.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/errno-base.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/int-ll64.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/bitops/*.h	include/asm-generic/bitops/
	@
	@
	@ cp $(REF_KERNEL)/include/asm-generic/atomic64.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/cmpxchg.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/div64.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/local.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/system.h		include/asm-generic/
	@
	@#cp $(REF_KERNEL)/arch/x86/include/asm/atomic_64.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/cmpxchg.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/div64.h		arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/local.h		arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/system.h	arch/x86/include/asm/
	@
	@
	@#cp $(REF_KERNEL)/arch/x86/include/asm/atomic.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/byteorder.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/checksum_64.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/cmpxchg_64.h	arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/page.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/posix_types_64.h arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/sync_bitops.h   arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unaligned.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unistd_64.h	arch/x86/include/asm/ 
