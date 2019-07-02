# usermode_compat/src/Makefile
# Makefile for usermode compatibility for Linux kernel source code
# Imports optional SYS_SERVICE_INCL, CFLAGS, MY_CFLAGS, EXTRA_CFLAGS, REF_KERNEL

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
MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables memory initialization; NVALGRIND disables all valgrind checks
# MY_CFLAGS += -DVALGRIND -DARENA_DISABLE=1
# MY_CFLAGS += -DNVALGRIND

ifndef SYS_SERVICE_INCL
### Place to get mtelib.h and sys_service.h (et. al.), if not in /usr/include
SYS_SERVICE_INCL=../../MTE/include
endif

MY_CFLAGS += -I$(SYS_SERVICE_INCL)
MTELIB_H := $(SYS_SERVICE_INCL)/mtelib.h

#######################  Enable most compiler warnings  #######################

# Warnings enabled by a real kernel build
WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wundef

# Warnings passed by MTE and by UMC and its included reference kernel files
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wfloat-conversion
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wunsafe-loop-optimizations

WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wswitch-enum
WFLAGS_WARN += -Wredundant-decls
WFLAGS_WARN += -Wformat=2

# This only warns if -fstrict-aliasing is enabled (e.g. by -O2), in which case the warning is important
WFLAGS_WARN += -Wstrict-aliasing

## Some of each of these in MTE code
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion
# WFLAGS_WARN += -Wpointer-arith

## Some of each of these in UMC code
# WFLAGS_WARN += -Wwrite-strings

### Some of each of these in code included from reference kernel 2.6.32
# WFLAGS_WARN += -Wswitch-default			# 1 in lib/bitmap.c
# WFLAGS_WARN += -Wcast-qual				# several in reference kernel files
WFLAGS_WARN += -Wbad-function-cast			# 1 in linux/kernel.h when compiling SCST/DRBD
WFLAGS_WARN += -Wshadow					# kernel.h, bitops.h when compiling SCST/DRBD
WFLAGS_INHIBIT += -Wno-sign-compare			# 3 in net/netlink.h, 1 in linux/skbuff.h
WFLAGS_INHIBIT += -Wno-implicit-fallthrough		# 1 in lib/nlattr.c

### silly
WFLAGS_INHIBIT += -Wno-unused-parameter

MY_CFLAGS += $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

###############################################################################

SHELL=/bin/bash

MY_CFLAGS += -g -ggdb -fno-omit-frame-pointer -D_GNU_SOURCE -fPIC -I. -isystem ./arch/x86/include -isystem include

SRCS_D = usermode_lib.c UMC_fuse.c
OBJS_D = $(SRCS_D:.c=.o)

all:	check_kcopy check_MTE
	$(MAKE) cscope
	$(MAKE) .depend
	$(MAKE) $(OBJS_D)

check_kcopy:
	@if [[ ! -d include ]] ; then $(MAKE) kcopy; fi

check_MTE:
	@if [[ ! -f /usr/include/mtelib.h && ! -f $(MTELIB_H) ]] ; then $(MAKE) need_MTE; fi

need_MTE:
	@echo "***** Install MTE header files into /usr/include or set Makefile SYS_SERVICE_INCL to point at MTE/include *****"

%.o: %.c check_kcopy check_MTE
	$(CC) -c -o $@ $(CFLAGS) $(MY_CFLAGS) $(EXTRA_CFLAGS) $<

ifeq (.depend,$(wildcard .depend))
-include .depend
endif

.depend:
	$(CC) -M $(CFLAGS) $(MY_CFLAGS) $(EXTRA_CFLAGS) $(SRCS_D) > $@

clean:
	rm -f *.o .depend
	rm -f tags cscope.out

extraclean: clean
	rm -f *.orig *.rej
	rm -rf include arch klib

cscope:
	@cscope -b -c -R
	@ctags        -R

.PHONY:	all check_kcopy check_MTE need_MTE clean extraclean cscope

#########################################################################

# Create a mostly-empty copy of the include and arch subdirectories of $(REF_KERNEL).
# First build an empty tree, then copy in the files we need.
# The empty tree provides non-failing, but empty, targets for #include directives.
# Usermode build uses the actual kernel headers copied below.

.PHONY:	kcopy _klib _kinclude

DIR := $(shell /bin/pwd)

kcopy:	_kinclude _klib
	@# These have been modified from the 2.6.32 reference kernel
	@ cp kincl_mod/netlink.h    include/net/
	@ cp kincl_mod/kernel.h	    include/linux/
	@ cp kincl_mod/types.h	    include/linux/
	@# These don't exist unless you have built the reference kernel
	@ touch			    include/linux/version.h
	@ touch			    include/linux/export.h
	@ touch			    include/linux/autoconf.h

_klib:
	@# Get some .c files from the reference kernel
	@ mkdir -p klib
	@ cp $(REF_KERNEL)/lib/bitmap.c				klib
	@#cp $(REF_KERNEL)/lib/libcrc32c.c			klib
	@ cp $(REF_KERNEL)/lib/rbtree.c				klib
	@ cp $(REF_KERNEL)/lib/dec_and_lock.c			klib
	@ $(MAKE) klib/idr.c
	@ $(MAKE) klib/nlattr.c

klib/idr.c:
	@ cp $(REF_KERNEL)/lib/idr.c				klib/idr.c
	@ echo "" >> klib/idr.c
	@ echo "void __exit idr_exit_cache(void) { kmem_cache_destroy(idr_layer_cache); }" >> klib/idr.c

klib/nlattr.c:
	@ cp $(REF_KERNEL)/lib/nlattr.c				klib/nlattr.c
	@ patch -p0 < kincl_mod/PATCH.nlattr.c

# The ones that are commented out will require more work than simply uncommenting them!
# They have never been tried nor had their depedencies determined

_kinclude:
	@# Get some .h files from the reference kernel
	@echo Copy selected kernel header files from $(REF_KERNEL) for inclusion by apps building for usermode
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
	@		    #included by linux/kernel.h
	@ cp $(REF_KERNEL)/arch/x86/include/asm/bitops.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/bug.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/byteorder.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/div64.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/linkage.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/types.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/include/asm-generic/bitops.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/bug.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/div64.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/linkage.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/types.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/linux/bitops.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/bug.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/linkage.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/log2.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/ratelimit.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/typecheck.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/types.h		include/linux/
	@
	@
	@ cp $(REF_KERNEL)/include/linux/bitmap.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/cache.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/crc32c.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/idr.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/ktime.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/list.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/poison.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/prefetch.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/rbtree.h		include/linux/
	@
	@#cp $(REF_KERNEL)/include/linux/bitrev.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/blkdev.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/cpumask.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/ctype.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/inet.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/kobject.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/kref.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/parser.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/plist.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/prio_heap.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/prio_tree.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/proportions.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/radix-tree.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rational.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/reciprocal_div.h	include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem-spinlock.h	include/linux/
	@#cp $(REF_KERNEL)/include/linux/sort.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/time.h			include/linux/
	@
	@
	@ cp $(REF_KERNEL)/include/linux/in.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/in6.h			include/linux/
	@ cp $(REF_KERNEL)/include/linux/skbuff.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/net.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/tcp.h			include/linux/
	@
	@ cp $(REF_KERNEL)/include/linux/genetlink.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/netlink.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/net/genetlink.h		include/net/
	@ cp $(REF_KERNEL)/include/net/netlink.h		include/net/
	@
	@#cp $(REF_KERNEL)/include/crypto/hash.h		include/crypto/
	@
	@ cp $(REF_KERNEL)/include/scsi/scsi_cmnd.h		include/scsi/
	@ cp $(REF_KERNEL)/include/scsi/scsi_eh.h		include/scsi/
	@ cp $(REF_KERNEL)/include/scsi/scsi.h			include/scsi/
	@
	@
	@ cp $(REF_KERNEL)/include/linux/kmemcheck.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/rwsem.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/spinlock.h		include/linux/
	@
	@ cp $(REF_KERNEL)/arch/x86/include/asm/kmemcheck.h	arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/rwsem.h		arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/spinlock.h	arch/x86/include/asm/
	@
	@
	@ cp $(REF_KERNEL)/include/net/checksum.h		include/net/
	@ cp $(REF_KERNEL)/include/linux/errno.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/ioctl.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/posix_types.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/scatterlist.h		include/linux/
	@#cp $(REF_KERNEL)/include/linux/socket.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/sockios.h		include/linux/
	@ cp $(REF_KERNEL)/include/linux/swab.h			include/linux/
	@#cp $(REF_KERNEL)/include/linux/unistd.h		include/linux/
	@
	@ cp $(REF_KERNEL)/include/asm-generic/checksum.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/errno.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/ioctl.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/posix_types.h	include/asm-generic/
	@#cp $(REF_KERNEL)/include/asm-generic/scatterlist.h	include/asm-generic/
	@#cp $(REF_KERNEL)/include/asm-generic/socket.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/sockios.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/swab.h		include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/unistd.h		include/asm-generic/
	@
	@ cp $(REF_KERNEL)/arch/x86/include/asm/checksum.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/errno.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/ioctl.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/posix_types.h	arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/scatterlist.h	arch/x86/include/asm/
	@#cp $(REF_KERNEL)/arch/x86/include/asm/socket.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/sockios.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/swab.h		arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unistd.h	arch/x86/include/asm/
	@
	@
	@ cp $(REF_KERNEL)/include/asm-generic/atomic-long.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/errno-base.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/int-ll64.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/bitops/*.h	include/asm-generic/bitops/
	@
	@
	@ cp $(REF_KERNEL)/include/asm-generic/atomic64.h	include/asm-generic/
	@ cp $(REF_KERNEL)/include/asm-generic/cmpxchg.h	include/asm-generic/
	@
	@ cp $(REF_KERNEL)/arch/x86/include/asm/atomic_64.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/cmpxchg.h	arch/x86/include/asm/
	@
	@
	@#cp $(REF_KERNEL)/arch/x86/include/asm/atomic.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/bitsperlong.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/checksum_64.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/cmpxchg_64.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/posix_types_64.h arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/sync_bitops.h   arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unaligned.h	arch/x86/include/asm/
	@ cp $(REF_KERNEL)/arch/x86/include/asm/unistd_64.h	arch/x86/include/asm/ 
	@ cp $(REF_KERNEL)/arch/x86/include/asm/alternative.h	arch/x86/include/asm/ 
	@ cp $(REF_KERNEL)/arch/x86/include/asm/asm.h		arch/x86/include/asm/ 
