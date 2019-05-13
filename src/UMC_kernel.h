/* UMC_kernel.h
 * Some random things lifted from real Linux kernel header files.
 */
#include <inttypes.h>

#ifndef UMC_KERNEL_H
#define UMC_KERNEL_H

#ifndef __KERNEL__
#define __KERNEL__			/* what we are compiling thinks it is kernel code */
#endif

#define KERNEL_VERSION(a,b,c)		(((a) << 16) + ((b) << 8) + (c))

#define BITS_PER_BYTE			8
#define BITS_PER_LONG			__BITS_PER_LONG
#define BYTES_PER_LONG			(BITS_PER_LONG/BITS_PER_BYTE)

#define MINORBITS			20
#define MINORMASK			((1U << MINORBITS) - 1)
#define MKDEV(major, minor)		(((major) << MINORBITS) | (minor))

//#define TCP_ESTABLISHED			1
#define SOL_TCP				6

typedef uint8_t				u8;
typedef uint16_t			u16;
typedef uint32_t			u32;
typedef uint64_t			u64;
typedef int8_t				s8;
typedef int16_t				s16;
typedef int32_t				s32;
typedef int64_t				s64;

#define do_div(n,base) ({			\
	uint32_t __base = (base);		\
	uint32_t __rem;				\
	__rem = ((uint64_t)(n)) % __base;	\
	(n) = ((uint64_t)(n)) / __base;		\
	__rem;					\
})

/* min()/max() that do strict type-checking. Lifted from the kernel. */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/* ... and their non-checking counterparts, also taken from the kernel. */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

#endif /* UMC_KERNEL_H */
