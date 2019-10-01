/* UMC_kernel.h
 * Some random definitions lifted from real Linux kernel header files.
 */
#ifndef UMC_KERNEL_H
#define UMC_KERNEL_H
#include <sys/types.h>		// size_t
#include <inttypes.h>		// uint32_t

/*** linux/version.h ***/

#define KERNEL_VERSION(a,b,c)		(((a) << 16) + ((b) << 8) + (c))

/*** compiler-gcc.h ***/

#define __must_be_array(a) \
    BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

/*** asm-generic/div64.h (64-bit #ifdef) ***/

#define do_div(n,base) ({			\
	uint32_t __base = (base);		\
	uint32_t __rem;				\
	__rem = ((uint64_t)(n)) % __base;	\
	(n) = ((uint64_t)(n)) / __base;		\
	__rem;					\
})

/*** linux/kdev_t.h (modified to usermode convention) ***/

#define MINORBITS			8 // 20 in real kernel
#define MINORMASK			((1U << MINORBITS) - 1)
#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))
#define MKDEV(major, minor)		(((major) << MINORBITS) | (minor))

/*** linux/time.h ***/

struct timezone {
    int     tz_minuteswest; /* minutes west of Greenwich */
    int     tz_dsttime;     /* type of dst correction */
};

/*** linux/dma-mapping.h ***/

enum dma_data_direction {
        DMA_BIDIRECTIONAL = 0,
        DMA_TO_DEVICE = 1,
        DMA_FROM_DEVICE = 2,
        DMA_NONE = 3,
};

#ifndef NO_UMC_SOCKETS

/*** linux/net.h ***/

#define SOCK_CLOEXEC    O_CLOEXEC
#define SOCK_NONBLOCK   O_NONBLOCK

enum sock_shutdown_cmd {
	SHUT_RD		= 0,
	SHUT_WR		= 1,
	SHUT_RDWR	= 2,
};

enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};

/*** linux/socket.h ***/

typedef unsigned short sa_family_t;

#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets          */
#define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
#define AF_INET         2       /* Internet IP Protocol         */
#define AF_INET6        10      /* IP version 6                 */

#define SOL_SOCKET      1
#define SOL_TCP		6

#define SO_DEBUG        1
#define SO_REUSEADDR    2
#define SO_DONTROUTE    5
#define SO_BROADCAST    6
#define SO_SNDBUF       7
#define SO_RCVBUF       8
#define SO_KEEPALIVE    9
#define SO_LINGER       13
#define SO_RCVLOWAT     18
#define SO_SNDLOWAT     19
#define SO_RCVTIMEO     20
#define SO_SNDTIMEO     21
#define SO_SNDBUFFORCE  32
#define SO_RCVBUFFORCE  33

struct ucred {
        uint32_t   pid;
        uint32_t   uid;
        uint32_t   gid;
};

#define MSG_DONTROUTE   4
#define MSG_DONTWAIT    0x40    /* Nonblocking io */
#define MSG_WAITALL     0x100   /* Wait for a full request */
#define MSG_NOSIGNAL    0x4000  /* Do not generate SIGPIPE */
#define MSG_MORE        0x8000  /* Sender will send more */

typedef size_t		__kernel_size_t;

struct msghdr {
        void    *       msg_name;       /* Socket name                  */
        int             msg_namelen;    /* Length of name               */
        struct iovec *  msg_iov;        /* Data blocks                  */
        __kernel_size_t msg_iovlen;     /* Number of blocks             */
        void    *       msg_control;    /* Per protocol magic (eg BSD file descriptor passing) */
        __kernel_size_t msg_controllen; /* Length of cmsg list */
        unsigned        msg_flags;
};

struct sockaddr {
        sa_family_t     sa_family;      /* address family, AF_xxx       */
        char            sa_data[14];    /* 14 bytes of protocol address */
};

#endif

#define _K_SS_MAXSIZE 128
#define _K_SS_ALIGNSIZE (__alignof__ (struct sockaddr *))
struct __kernel_sockaddr_storage {
        unsigned short  ss_family;
        char            __data[_K_SS_MAXSIZE - sizeof(unsigned short)];
} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));

#ifndef NO_UMC_SOCKETS
#define sockaddr_storage	__kernel_sockaddr_storage
#endif

/*** linux/tcp.h ***/

#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

/******************************************************************************/
// New for coccified DRBD

#define min_not_zero(x, y) ({                   \
        typeof(x) __x = (x);                    \
        typeof(y) __y = (y);                    \
        __x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })

#define for_each_set_bit(bit, addr, size) \
        for ((bit) = find_first_bit((addr), (size)); \
             (bit) < (size); \
             (bit) = find_next_bit((addr), (size), (bit) + 1))

#define list_first_entry_or_null(ptr, type, member) \
        (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

#define time_after(a,b)         \
        (typecheck(unsigned long, a) && \
         typecheck(unsigned long, b) && \
         ((long)((b) - (a)) < 0))
#define time_before(a,b)        time_after(b,a)

#define time_after_eq(a,b)      \
        (typecheck(unsigned long, a) && \
         typecheck(unsigned long, b) && \
         ((long)((a) - (b)) >= 0))
#define time_before_eq(a,b)     time_after_eq(b,a)

#define time_in_range(a,b,c) \
        (time_after_eq(a,b) && \
         time_before_eq(a,c))

/* Caller must be guard these RCU list functions with rcu_read_lock() */

#define list_entry_rcu(ptr, type, member) \
({ \
        typeof(*ptr) __rcu *__ptr = (typeof(*ptr) __rcu __force *)ptr; \
        container_of((typeof(ptr))rcu_dereference_raw(__ptr), type, member); \
})

#define list_first_or_null_rcu(ptr, type, member) \
({ \
        struct list_head *__ptr = (ptr); \
        struct list_head *__next = ACCESS_ONCE(__ptr->next); \
        likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})

#define list_for_each_entry_continue_rcu(pos, head, member)             \
        for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
             &pos->member != (head);    \
             pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

#endif /* UMC_KERNEL_H */
