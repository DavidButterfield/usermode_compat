/* UMC_kernel.h
 * Some random things lifted from real Linux kernel header files.
 */
#ifndef UMC_KERNEL_H
#define UMC_KERNEL_H

#ifndef __KERNEL__
#define __KERNEL__			/* what we are compiling thinks it is kernel code */
#endif

#define KERNEL_VERSION(a,b,c)		(((a) << 16) + ((b) << 8) + (c))

#define BITS_PER_LONG			__BITS_PER_LONG
#define BYTES_PER_LONG			(BITS_PER_LONG/8)

typedef uint8_t				bool;
typedef uint8_t				u8;
typedef uint16_t			u16;
typedef uint32_t			u32;
typedef uint64_t			u64;
typedef int32_t				s32;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8 *)res = *(const volatile __u8 *)p; break;
	case 2: *(__u16 *)res = *(const volatile __u16 *)p; break;
	case 4: *(__u32 *)res = *(const volatile __u32 *)p; break;
	case 8: *(__u64 *)res = *(const volatile __u64 *)p; break;
	default:
	    fprintf(stderr, "FATAL: __read_once_size(%p, %p(0x%llx) %u)", p, res, *(__u64 *)res, size);
	    exit(-9);
	}
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile __u8 *)p = *(__u8 *)res; break;
	case 2: *(volatile __u16 *)p = *(__u16 *)res; break;
	case 4: *(volatile __u32 *)p = *(__u32 *)res; break;
	case 8: *(volatile __u64 *)p = *(__u64 *)res; break;
	default:
	    fprintf(stderr, "FATAL: __write_once_size(%p, %p(0x%llx) %u)", p, res, *(__u64 *)res, size);
	    exit(-9);
	}
}

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u;	\
	__read_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (typeof(x)) (val) }; \
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define __ACCESS_ONCE(x) ({ (volatile typeof(x) *)&(x); })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))

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

#define do_div(n,base) ({					\
        uint32_t __base = (base);                               \
        uint32_t __rem;                                         \
        __rem = ((uint64_t)(n)) % __base;                       \
        (n) = ((uint64_t)(n)) / __base;                         \
        __rem;                                                  \
})

/* Some unused kernel types wanted by parts of kernel's list.h we don't use */
struct rq_disk { void * private_data; };
struct request { struct request * next_rq; void * special; struct rq_disk * rq_disk; };
struct list_head { struct list_head *next, *prev; };
struct hlist_head { struct hlist_node *first; };
struct hlist_node { struct hlist_node *next, **pprev; };
#define LIST_POISON1  ((void *) 0x00100100 )
#define LIST_POISON2  ((void *) 0x00200200 )

#endif /* UMC_KERNEL_H */
