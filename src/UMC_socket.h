/* UMC_socket.h -- usermode compatibility for kernel sockets
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_SOCKET_H
#define UMC_SOCKET_H
#include "UMC_sys.h"
#include "UMC_file.h"
#include "UMC_thread.h"

struct page;
struct socket;
struct sock;
enum sock_type;
struct poll_table_struct { };
struct ts_config;
struct ts_state;
#include "include/net/checksum.h"
#include "include/linux/skbuff.h"
#include "include/linux/in.h"
#include "include/linux/in6.h"
/* do not include <linux/socket.h> */

struct sk_prot {
    void		  (*disconnect)(struct sock *, int);
};

struct sock {
    int			    fd;			    /* same as inode->UMC_fd (backing fd) */
    uint16_t		    sk_sport;
    uint16_t		    sk_dport;

    long		    sk_rcvtimeo;
    long		    UMC_rcvtimeo;	    /* last timeout set in real socket */
    long		    sk_sndtimeo;	    //XXX ignored
    int			    sk_rcvbuf;		    //XXX ignored
    int			    sk_sndbuf;		    //XXX ignored

    struct socket	  * sk_socket;		    /* unimplemented */
    __u32		    sk_priority;	    /* unimplemented */
    int			    sk_wmem_queued;	    /* unimplemented */
    gfp_t		    sk_allocation;	    /* unimplemented */
    unsigned char	    sk_reuse:4;		    /* unimplemented */
    unsigned char	    sk_userlocks:4;	    /* unimplemented */

    int			    sk_state;		    /* e.g. TCP_ESTABLISHED */
    rwlock_t		    sk_callback_lock;	    /* protect changes to callbacks */	//XXXXX unused!
    void		  * sk_user_data;
    void		  (*sk_data_ready)(struct sock *, int); /* protocol callbacks */
    void		  (*sk_write_space)(struct sock *);
    void		  (*sk_state_change)(struct sock *);
    struct sk_prot	  * sk_prot;
    struct sk_prot	    sk_prot_s;

    /* TCP */
    u32			    copied_seq;		    /* unimplemented */
    u32			    rcv_nxt;		    /* unimplemented */
    u32			    snd_una;		    /* unimplemented */
    u32			    write_seq;		    /* unimplemented */

    bool		    is_listener;

    /* Netlink */
    struct sock		  * sk;		/* self-pointer hack */
    struct netlink_callback *cb;
    struct mutex	  * cb_mutex;
    struct mutex	    cb_def_mutex;
    void		    (*netlink_rcv)(struct sk_buff *skb);

    sys_event_task_t	    wr_poll_event_task;	/* thread of event thread for this fd */
    sys_poll_entry_t	    wr_poll_entry;	/* unique poll descriptor for this fd */
    sys_event_task_t	    rd_poll_event_task;
    sys_poll_entry_t	    rd_poll_entry;
    struct task_struct    * rd_poll_event_thread;

    uint16_t sk_family;
    union {
	struct {
	    struct in_addr saddr;
	    struct in_addr daddr;
	} inet_sk;
	struct {
	    struct in6_addr saddr;
	    struct in6_addr daddr;
	} inet6_sk;
    };
};

#define	tcp_sock			sock
#define TCP_ESTABLISHED			1

static inline struct tcp_sock *
tcp_sk(struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

//XXX IPv6 has never been tested */
#define inet_sk(sk)			(&(sk)->inet_sk)
#define inet6_sk(sk)			(&(sk)->inet6_sk)

#define IPV6_ADDR_LINKLOCAL		0x0020U
#define IPV6_ADDR_UNICAST		0x0001U
#define ipv6_addr_type(x)		IPV6_ADDR_UNICAST   //XXX LINKLOCAL ?

#define ipv6_addr_equal(x, y)		(!memcmp((x), (y), sizeof(struct in6_addr)))

#define NIP6(addr)			(addr).s6_addr16[0], \
					(addr).s6_addr16[1], \
					(addr).s6_addr16[2], \
					(addr).s6_addr16[3], \
					(addr).s6_addr16[4], \
					(addr).s6_addr16[5], \
					(addr).s6_addr16[6], \
					(addr).s6_addr16[7]

struct socket_ops {
    ssize_t (*sendpage)  (struct socket *, struct page *, int, size_t, int);
    int     (*setsockopt)(struct socket *, int, int, void *, socklen_t);
    int     (*getname)   (struct socket *, struct sockaddr *, socklen_t *addr_len, int peer);
    int     (*bind)	 (struct socket *, struct sockaddr *, socklen_t addr_len);
    int     (*connect)   (struct socket *, struct sockaddr *, socklen_t addr_len, int flags);
    int     (*listen)    (struct socket *, int len);
    int     (*accept)    (struct socket *, struct socket *, int flags, bool kern);
    int     (*shutdown)  (struct socket *, int);
    void    (*discon)	 (struct socket *);
};

#define RCV_SHUTDOWN			1
#define SEND_SHUTDOWN			2

typedef enum { SS_unused } socket_state;

struct socket {
    struct inode	    vfs_inode;
    socket_state	    state;
    unsigned long	    flags;
    bool		    nonblocking;	/* NONBLOCK setting */
    struct file		  * file;
    struct sock		  * sk;			/* points at embedded sk_s */
    struct socket_ops     * ops;		/* points at embedded ops_s */
    struct sock		    sk_s;
    struct socket_ops	    ops_s;
};

#define SOCKET_I(inode)			({ assert_eq((inode)->UMC_type, I_TYPE_SOCK); \
					   container_of((inode), struct socket, vfs_inode); \
					})

#define sock_of_sk(sk)			container_of((sk), struct socket, sk_s)

#define ip_compute_csum(data, len)	0	//XXX

#define SOCK_SNDBUF_LOCK		1
#define SOCK_RCVBUF_LOCK		2
#define SOCK_NOSPACE			2

#define kernel_accept(sock, newsock, flags)	    UMC_sock_accept((sock), (newsock), (flags))
#define kernel_sock_shutdown(sock, k_how)	    UMC_sock_shutdown((sock), (k_how))
#define kernel_setsockopt(sock, level, optname, optval, optlen) \
	    UMC_setsockopt(sock, level, optname, optval, optlen)

/* The sock->ops point to these shim functions */
extern ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
				size_t size, int flags);
extern error_t UMC_setsockopt(struct socket * sock, int level, int optname,
				void *optval, socklen_t optlen);
extern error_t UMC_sock_connect(struct socket * sock, struct sockaddr * addr,
				socklen_t addrlen, int flags);
extern error_t UMC_sock_bind(struct socket * sock, struct sockaddr *addr, socklen_t addrlen);
extern error_t UMC_sock_listen(struct socket * sock, int backlog);
extern error_t UMC_sock_accept(struct socket * sock, struct socket ** newsock, int flags);
extern error_t UMC_sock_shutdown(struct socket * sock, int k_how);
extern void UMC_sock_discon(struct sock * sk, int XXX);
extern error_t UMC_sock_getname(struct socket * sock, struct sockaddr * addr,
				socklen_t * addrlen, int peer);

/* These are the original targets of the sk callbacks before the app intercepts them */
extern void UMC_sock_cb_read(struct sock *, int obsolete);
extern void UMC_sock_cb_write(struct sock *);
extern void UMC_sock_cb_state(struct sock *);

extern void UMC_sock_recv_event(void * env, uintptr_t events, error_t err);
extern void UMC_sock_xmit_event(void * env, uintptr_t events, error_t err);

struct msghdr;
extern ssize_t kernel_sendmsg(struct socket * sock, struct msghdr * msg,
				struct kvec * vec, int nvec, size_t nbytes);

#define sock_recvmsg(sock, msg, nb, f) \
	    UMC_sock_recvmsg((sock), (msg), (nb), (f), FL_STR)
extern error_t UMC_sock_recvmsg(struct socket * sock, struct msghdr * msg,
		size_t nbytes, int flags, sstring_t caller_id);

#define kernel_recvmsg(sock, msg, vec, nsg, nb, f) \
	    UMC_kernel_recvmsg((sock), (msg), (vec), (nsg), (nb), (f), FL_STR)
extern error_t UMC_kernel_recvmsg(struct socket * sock, struct msghdr * msg,
			struct kvec * kvec, int num_sg, size_t nbytes,
			int flags, sstring_t caller_id);

/* Initialize a socket structure around an open socket fd */
static inline void
UMC_sock_init(struct socket * sock, struct file * file)
{
    int fd = file->inode->UMC_fd;

    /* Set pointers to internal embedded structures */
    sock->ops = &sock->ops_s;
    sock->sk = &sock->sk_s;
    sock->sk->sk_prot = &sock->sk->sk_prot_s;

    sock->sk->fd = fd;
    sock->file = file;
    sock->flags = 0;

    /* Socket operations callable by application */
    struct socket_ops * wops = (struct socket_ops *)sock->ops;
    wops->bind = UMC_sock_bind;
    wops->connect = UMC_sock_connect;
    wops->getname = UMC_sock_getname;
    wops->listen = UMC_sock_listen;
    wops->shutdown = UMC_sock_shutdown;
    wops->setsockopt = UMC_setsockopt;
    wops->sendpage = sock_no_sendpage;
    sock->sk->sk_prot->disconnect = UMC_sock_discon;

    /* State change callbacks to the application, delivered by event_task */
    sock->sk->sk_state_change = UMC_sock_cb_state;
    sock->sk->sk_data_ready = UMC_sock_cb_read;
    sock->sk->sk_write_space = UMC_sock_cb_write;

    rwlock_init(&sock->sk->sk_callback_lock);
}

extern int UMC_socketpair(int domain, int type, int protocol, int sv[2]);
extern void UMC_sock_filladdrs(struct socket * sock);

//XXXX TUNE how sockets relate to event threads
/* For now using one "softirq" thread for transmit-ready notifications shared by
 * ALL sockets, and one softirq thread for receive processing for EACH socket.
 */
static inline void
UMC_sock_poll_start(struct socket * sock, void (*recv)(struct sock *, int),
					  void (*xmit)(struct sock *),
					  void (*state)(struct sock *),
					  sstring_t recv_thread_name)
{
    sock->sk->sk_data_ready = recv ?: UMC_sock_cb_read;
    sock->sk->sk_write_space = xmit ?: UMC_sock_cb_write;
    sock->sk->sk_state_change = state ?: UMC_sock_cb_state;
    if (xmit) {
	sock->sk->wr_poll_event_task = UMC_irqthread->event_task;
	sock->sk->wr_poll_entry = sys_poll_enable(sock->sk->wr_poll_event_task,
					  UMC_sock_xmit_event, sock, sock->sk->fd,
					  SYS_SOCKET_XMIT_ET, "socket_xmit_poll_entry");
    }
    if (recv || state) {
	struct sys_event_task_cfg cfg = {
	    .max_polls = SYS_ETASK_MAX_POLLS,
	    .max_steps = SYS_ETASK_MAX_STEPS,
	};
	sock->sk->rd_poll_event_thread = irqthread_run(&cfg, "%s", recv_thread_name);
	sock->sk->rd_poll_event_task = sock->sk->rd_poll_event_thread->event_task;
	sock->sk->rd_poll_entry = sys_poll_enable(sock->sk->rd_poll_event_task,
					  UMC_sock_recv_event, sock, sock->sk->fd,
					  SYS_SOCKET_RECV_ET, "socket_recv_poll_entry");
    }
}

extern void sock_inode_destructor(struct inode *);

/* Wrap a backing real usermode SOCKET fd inside a simulated kernel struct file * */
//XXX Support for fget/fput presently limited to sockets, one reference only
static inline struct file *
_fget(unsigned int fd)
{
    struct file * file = record_alloc(file);
    struct socket * sock = record_alloc(sock);
    //XXX should assert that fd represents a real socket
    file->inode = &sock->vfs_inode;
    init_inode(file->inode, I_TYPE_SOCK, 0, 0, 0, fd);
    file->inode->UMC_destructor = sock_inode_destructor;
    UMC_sock_init(SOCKET_I(file->inode), file);
    return file;
}

/* This is used by SCST to grab an fd already opened by the usermode daemon */
static inline struct file *
fget(unsigned int real_fd)
{
    int fd = dup(real_fd);
    if (fd < 0) {
	pr_warning("fget could not dup() incoming fd=%d err=%d\n", real_fd, errno);
	return NULL;
    }
    struct file * file = _fget(fd);	/* caller still owns the original fd */
    struct socket * sock = SOCKET_I(file->inode);
    char thread_name[32];
    UMC_sock_filladdrs(sock);
    sock->sk->sk_state = TCP_ESTABLISHED;
    snprintf(thread_name, sizeof(thread_name), "%d.%d.%d.%d",
						NIPQUAD(inet_sk(sock->sk)->daddr));
    /* use whatever callbacks are already in the sk */
    UMC_sock_poll_start(sock, sock->sk->sk_data_ready, sock->sk->sk_write_space,
						sock->sk->sk_state_change, thread_name);
    return file;
}

extern int UMC_socket(int domain, int type, int protocol);

/* Does not enable poll events or start a receive handler thread for the socket */
static inline int
sock_create_kern(int family, int type, int protocol, struct socket **newsock)
{
    int fd = UMC_socket(family, type, protocol);
    if (unlikely(fd < 0)) {
	*newsock = NULL;
	return fd;	/* -errno */
    }

    struct file * file = _fget(fd);
    if (!file) {
	close(fd);
	*newsock = NULL;
	return -ENOMEM;
    }

    *newsock = SOCKET_I(file->inode);

    if(type & SOCK_NONBLOCK)
	(*newsock)->nonblocking = true;

    return 0;
}

struct fput_finish_work {
    struct task_struct		  * irqthread;
    struct work_struct		    work;
};

static inline void
_fput_finish_work_fn(struct task_struct * irqthread)
{
    irqthread_stop(irqthread);
}

static inline void
fput_finish_work_fn(struct work_struct * work)
{
    struct fput_finish_work * ffw;
    ffw = container_of(work, struct fput_finish_work, work);
    _fput_finish_work_fn(ffw->irqthread);
    record_free(ffw);
}

static inline void
fput(struct file * sockfile)
{
    assert_eq(sockfile->inode->UMC_type, I_TYPE_SOCK);
    struct sock * sk = SOCKET_I(sockfile->inode)->sk;

    if (sk->wr_poll_event_task)
	sys_poll_disable(sk->wr_poll_event_task, sk->wr_poll_entry);

    if (sk->rd_poll_event_task) {
	sys_poll_disable(sk->rd_poll_event_task, sk->rd_poll_entry);

	if (sys_thread_current() != sk->rd_poll_event_thread->SYS)  //XXX
	    _fput_finish_work_fn(sk->rd_poll_event_thread);
	else {
	    /* irqthread can't shut itself down; use a helper */
	    struct fput_finish_work * ffw = record_alloc(ffw);
	    INIT_WORK(&ffw->work, fput_finish_work_fn);
	    ffw->irqthread = sk->rd_poll_event_thread;
	    schedule_work(&ffw->work);
	}
    }

    iput(sockfile->inode);
    record_free(sockfile);
}

#define sock_release(sock)		fput((sock)->file)

#endif /* UMC_SOCKET_H */
