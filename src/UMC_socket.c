/* UMC_socket.c
 * Compatibility for kernel code running in usermode
 * Copyright 2016-2019 David A. Butterfield
 */
#define _GNU_SOURCE

#define  NO_UMC_SOCKETS	    // inhibit usermode_lib ucred for one in sys/socket.h
#include <sys/socket.h>
#include </usr/include/asm-generic/socket.h> /* sys/socket.h included the wrong asm/socket.h */
#include "UMC_socket.h"	    // must be after sys/socket.h, when NO_UMC_SOCKETS

#define trace_socket(fmtargs...)	    //	nlprintk(fmtargs)
#define trace_socket_verbose(fmtargs...)    //	nlprintk(fmtargs)

void
sock_inode_destructor(struct inode * inode)
{
    trace_socket("CLOSE socket fd=%d", inode->UMC_fd);
    assert_ge(inode->UMC_fd, 0);
    close(inode->UMC_fd);
    record_free(SOCKET_I(inode));   /* inode embedded */
}

void
UMC_sock_filladdrs(struct socket * sock)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t addrlen = (int)sizeof(addr);
    int rc;
    rc = getpeername(sock->sk->fd, &addr, &addrlen);
    if (likely(rc == 0)) {
	sock->sk->sk_family = addr.sin_family;
	inet_sk(sock->sk)->daddr = addr.sin_addr;
	sock->sk->sk_dport = addr.sin_port;
    }
    rc = getsockname(sock->sk->fd, &addr, &addrlen);
    if (likely(rc == 0)) {
	inet_sk(sock->sk)->saddr = addr.sin_addr;
	sock->sk->sk_sport = addr.sin_port;
    }
}

error_t
UMC_socket(int family, int type, int protocol)
{
    return UMC_kernelize(socket(family, type, protocol));
}

error_t
UMC_socketpair(int domain, int type, int protocol, int sv[2])
{
   return UMC_kernelize(socketpair(domain, type, protocol, sv));
}

error_t
UMC_setsockopt(struct socket * sock, int level, int optname, void *optval, socklen_t optlen)
{
    error_t ret = UMC_kernelize(setsockopt(sock->sk->fd, level, optname, optval, optlen));
    trace_socket("%s (%d) SETSOCKOPT fd=%d level=%d optname=%d optval=0x%x optlen=%d returns %d",
		current->comm, current->pid, sock->sk->fd,
		level, optname, *(int *)optval, optlen, ret);
    return ret;
}

/* Note: The semantics of the arguments to the kernel function and C-library function differ.
 *	 The kernel function ignores the incoming addrlen and assumes it is big enough.  The
 *	 peer argument is intended to be 0 to get the local address, nonzero to get the peer
 *	 address, with 1 denoting to return the peer address only if connected.
 */
error_t
UMC_sock_getname(struct socket * sock, struct sockaddr * addr, socklen_t * addrlen, int peer)
{
    *addrlen = sizeof(struct sockaddr_in);
    if (peer) {
	if (peer == 1)
	    return UMC_kernelize(getpeername(sock->sk->fd, addr, addrlen));
	else {
	    struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
	    memset(inaddr, 0, *addrlen);
	    inaddr->sin_family = sock->sk->sk_family;
	    inaddr->sin_port = sock->sk->sk_dport;
	    inaddr->sin_addr = sock->sk->inet_sk.daddr;
	    return 0;
	}
    } else
	return UMC_kernelize(getsockname(sock->sk->fd, addr, addrlen));
}

/* Does not enable poll events or start a receive handler thread for the socket */
error_t
UMC_sock_connect(struct socket * sock, struct sockaddr * addr, socklen_t addrlen, int flags)
{
    //XXX UMC_sock_connect flags ?
    __attribute__((__unused__))
    struct sockaddr_in * inaddr = (struct sockaddr_in *)addr;
    trace_socket("%s (%d) connecting socket fd=%d to %d.%d.%d.%d port %u",
		current->comm, current->pid, sock->sk->fd,
		NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port));

    error_t err = UMC_kernelize(connect(sock->sk->fd, addr, addrlen));
    if (!err) {
	sock->sk->sk_state = TCP_ESTABLISHED;
	UMC_sock_filladdrs(sock);
    }

    trace_socket("%s (%d) connected socket fd=%d to %d.%d.%d.%d port %u err=%d",
		current->comm, current->pid, sock->sk->fd,
		NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port), err);
    return err;
}

error_t
UMC_sock_bind(struct socket * sock, struct sockaddr *addr, socklen_t addrlen)
{
    error_t err = -ENOPROTOOPT;
    assert_eq(addr->sa_family, AF_INET);

    if (addr->sa_family == AF_INET) {
	struct sockaddr_in * inaddr = (struct sockaddr_in *)addr;
	if (inaddr->sin_port != 0) {
	    int optval = true;
	    //XXX Should leave setting SO_REUSEADDR to the app -- see also SK_CAN_REUSE
	    UMC_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));	//XXX
	}

	err = UMC_kernelize(bind(sock->sk->fd, addr, addrlen));
	if (!err) {
	    trace_socket("%s (%d) binds socket fd=%d to %d.%d.%d.%d port %u",
			current->comm, current->pid, sock->sk->fd,
			NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port));
	    UMC_sock_filladdrs(sock);
	} else {
	    pr_warning("%s (%d) ERROR %d binding fd=%d to %d.%d.%d.%d port %u\n",
			current->comm, current->pid, err, sock->sk->fd,
			NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port));
	}
    }

    return err;
}

error_t
UMC_sock_listen(struct socket * sock, int backlog)
{
    error_t ret = UMC_kernelize(listen(sock->sk->fd, backlog));
    if (ret != 0)
	return ret;

    if (sock->sk->sk_state_change == UMC_sock_cb_state)
	pr_warning("Listening on sockfd=%d with unset sk_state_change\n", sock->sk->fd);

    sock->sk->is_listener = true;
    UMC_sock_poll_start(sock, NULL, NULL, sock->sk->sk_state_change, "listener");
    return ret;
}

/* Does not enable poll events or start a receive handler thread for the socket */
error_t
UMC_sock_accept(struct socket * listener, struct socket ** newsock, int flags)
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    assert(listener->sk->is_listener);
    expect_eq(flags & ~SOCK_NONBLOCK, 0);   /* other flags untried */

    int newfd = UMC_kernelize(accept4(listener->sk->fd, &addr, &addrlen, flags));
    if (newfd < 0) {
	*newsock = NULL;
	pr_warning("Accept failed listenfd=%d err=%d\n", listener->sk->fd, newfd);
	return newfd;  /* -errno */
    }

    /* Wrap a file/inode/sock/sk around the newfd we just accepted */
    struct file * file = _fget(newfd);
    if (!file) {
	close(newfd);
	return -ENOMEM;
    }

    *newsock = SOCKET_I(file->inode);
    assert_eq((*newsock)->sk->fd, newfd);

    UMC_sock_filladdrs(*newsock);	/* get the local and peer addresses */
    (*newsock)->sk->sk_state = TCP_ESTABLISHED;

    if(flags & SOCK_NONBLOCK)
	(*newsock)->nonblocking = true;

    (*newsock)->sk->sk_state_change = listener->sk->sk_state_change;	//XXX Right? Why?

    trace_socket("Accepted incoming socket connection listenfd=%d newfd=%d peer_port=%d",
		listener->sk->fd, newfd, ntohs((*newsock)->sk->sk_dport));

    return 0;
}

error_t
UMC_sock_shutdown(struct socket * sock, int k_how)
{
    int u_how;
    if ((k_how & RCV_SHUTDOWN) && (k_how & SEND_SHUTDOWN))
	u_how = SHUT_RDWR;
    else if (k_how & RCV_SHUTDOWN)
	u_how = SHUT_RD;
    else if (k_how & SEND_SHUTDOWN)
	u_how = SHUT_WR;
    else {
	pr_warning("UMC_sock_shutdown called with bad flags 0x%x\n", k_how);
	u_how = SHUT_RDWR;
    }
    return shutdown(sock->sk->fd, u_how);
}

//XXX What is the precise difference between disconnect and shutdown(RW)?
//XXX Where is the intended semantic of sk_prot->disconnect documented?
void
UMC_sock_discon(struct sock * sk, int XXX)
{
    struct socket * sock = container_of(sk, struct socket, sk_s);
    UMC_sock_shutdown(sock, SHUT_RDWR);
}

ssize_t
kernel_sendmsg(struct socket * sock, struct msghdr *msg,
			struct kvec * vec, int nvec, size_t nbytes)
{
    msg->msg_iov = vec;
    msg->msg_iovlen = nvec;
    return UMC_kernelize64(sendmsg(sock->sk->fd, msg, msg->msg_flags));
}

ssize_t
sock_no_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
    return UMC_kernelize64(send(sock->sk->fd,
			    (char *)page_address(page) + offset, size, flags));
}

error_t
UMC_sock_recvmsg(struct socket * sock, struct msghdr * msg,
	      size_t nbytes, int flags, sstring_t caller_id)
{
    ssize_t rc = 123456789;
#ifdef DEBUG
    struct iovec * iov = msg->msg_iov;
    int niov = (int)msg->msg_iovlen;
    size_t msgbytes = 0;
    while (niov) {
	msgbytes += iov->iov_len;
	++iov;
	--niov;
    }
    expect_eq(nbytes, msgbytes);
#endif
#if 1	/* receive timeouts */
    if (sock->sk->sk_rcvtimeo != sock->sk->UMC_rcvtimeo) {
	/* somebody changed the receive timeout */
	sock->sk->UMC_rcvtimeo = sock->sk->sk_rcvtimeo;
	unsigned long usec = sock->sk->UMC_rcvtimeo < JIFFY_MAX
				    ? jiffies_to_usecs(sock->sk->UMC_rcvtimeo) : 0;
	struct timeval optval = {
	    .tv_sec  = usec / (1000*1000),
	    .tv_usec = usec % (1000*1000)
	};
	error_t err = UMC_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof(optval));
	if (err) {
	    pr_warning("%s: fd=%d failed to set receive timeout to jiffies=%lu sec=%lu usec=%lu\n",
		caller_id, sock->sk->fd, sock->sk->UMC_rcvtimeo, optval.tv_sec, optval.tv_usec);
	} else {
	    trace_socket("%s: fd=%d changed receive timeout to jiffies=%lu sec=%lu usec=%lu",
		caller_id, sock->sk->fd, sock->sk->UMC_rcvtimeo, optval.tv_sec, optval.tv_usec);
	}
    }
#endif

    sys_time_t t_end = sys_time_now() + jiffies_to_sys_time(sock->sk->UMC_rcvtimeo);
restart:
    rc = UMC_kernelize64(recvmsg(sock->sk->fd, msg, flags));

    /* Note from drbd:
     * -EINTR	     (on meta) we got a signal
     * -EAGAIN       (on meta) rcvtimeo expired
     * -ECONNRESET   other side closed the connection
     * -ERESTARTSYS  (on data) we got a signal
     * rv <  0       other than above: unexpected error!
     * rv == expected: full header or command
     * rv <  expected: "woken" by signal during receive
     * rv == 0       : "connection shut down by peer"
     */
    if (rc > 0) {
	if ((size_t)rc < nbytes) {
	    trace_socket("%s: received short read %ld/%lu on fd=%d flags=0x%x",
			caller_id, rc, nbytes, sock->sk->fd, flags);
	} else {
	    trace_socket_verbose("%s: received full read %ld/%lu on fd=%d flags=0x%x",
	        caller_id, rc, nbytes, sock->sk->fd, flags);
	}

	/* Advance the msg by the number of bytes we received into it */
	size_t skipbytes = (size_t)rc;
	while (skipbytes && skipbytes >= msg->msg_iov->iov_len) {
	    // msg->msg_iov->iov_base += msg->msg_iov->iov_len; //XXX needed?
	    skipbytes -= msg->msg_iov->iov_len;
	    msg->msg_iov->iov_len = 0;
	    ++msg->msg_iov;
	    assert_ne(msg->msg_iovlen, 0);
	    --msg->msg_iovlen;
	}
	if (skipbytes) {
	    /* It's not OK to do the add when skipbytes == zero */
	    msg->msg_iov->iov_base = (char *)msg->msg_iov->iov_base + skipbytes;
	    msg->msg_iov->iov_len -= skipbytes;
	}
    } else if (rc == 0) {
	trace_socket("%s: EOF on fd=%d flags=0x%x", caller_id, sock->sk->fd, flags);
    } else {
	if (rc == -EINTR) {
	    trace_socket("%s: recvmsg returns -EINTR on fd=%d flags=0x%x",
			    caller_id, sock->sk->fd, flags);
	} else if (rc == -EAGAIN) {
	    if (!sock->nonblocking && !(flags & MSG_DONTWAIT)) {
		if (sock->sk->UMC_rcvtimeo == 0 || sock->sk->UMC_rcvtimeo >= JIFFY_MAX) {
		    trace_socket("%s: recvmsg ignores -EAGAIN on fd=%d flags=0x%x", caller_id, sock->sk->fd, flags);
		    usleep(500);	    //XXXXX
		    goto restart;   //XXX doesn't adjust time remaining
		}
		#define T_SLOP jiffies_to_sys_time(1)
		if (sys_time_now() < t_end - T_SLOP) {
		    trace_socket("%s: recvmsg ignores early -EAGAIN on fd=%d now=%lu end=%lu flags=0x%x",
				caller_id, sock->sk->fd, sys_time_now(), t_end, flags);
		    usleep(500);	    //XXXXX
		    goto restart;   //XXX doesn't adjust time remaining
		}
		trace_socket("%s: recvmsg returns -EAGAIN on fd=%d timeout=%lu jiffies flags=0x%x",
			    caller_id, sock->sk->fd, sock->sk->sk_rcvtimeo, flags);
	    } else {
		trace_socket_verbose("%s: recvmsg(MSG_DONTWAIT) returns -EAGAIN on fd=%d timeout=%lu jiffies flags=0x%x",
			    caller_id, sock->sk->fd, sock->sk->sk_rcvtimeo, flags);
	    }
	} else {
	    pr_warning("%s: ERROR %"PRId64" '%s'on fd=%d flags=0x%x\n", caller_id,
			    rc, strerror((int)-rc), sock->sk->fd, flags);
	}
    }
    return (int)rc;
}

//XXXX Probably doesn't need the "skip" from UMC_sock_recvmsg()
error_t
UMC_kernel_recvmsg(struct socket * sock, struct msghdr * msg, struct kvec * kvec,
		int num_sg, size_t nbytes, int flags, sstring_t caller_id)
{
    msg->msg_iov = kvec;
    msg->msg_iovlen = num_sg;
    return UMC_sock_recvmsg(sock, msg, nbytes, flags, caller_id);
}

/* These are the original targets of the sk callbacks before the app intercepts them --
 * Because our event model here is EDGE TRIGGERED, we can get away with doing nothing
 */
void UMC_sock_cb_read(struct sock * sk, int obsolete)	\
	    { WARN_ONCE(true, "fd=%d", sk->fd); }
void UMC_sock_cb_write(struct sock * sk)		\
	    { WARN_ONCE(true, "fd=%d", sk->fd); }
void UMC_sock_cb_state(struct sock * sk)		\
	    { WARN_ONCE(true, "fd=%d", sk->fd); }

/* Callback on event_task when socket fd ready, dispatches to XMIT and/or RECV sk callback */
void
UMC_sock_xmit_event(void * env, uintptr_t events, error_t err)
{
    struct socket * sock = env;
    if (unlikely(err)) {
	sock->sk->sk_state_change(sock->sk);
	return;
    }

    if (unlikely(events & SYS_SOCKET_ERR)) {
	if (events & (EPOLLHUP | EPOLLERR)) {
	    sock->sk->sk_state &= ~TCP_ESTABLISHED;
	}
	sock->sk->sk_state_change(sock->sk);
    }

    if (likely(events & SYS_SOCKET_XMIT)) {
	sock->sk->sk_write_space(sock->sk);
    }
}

void
UMC_sock_recv_event(void * env, uintptr_t events, error_t err)
{
    struct socket * sock = env;
    if (unlikely(err)) {
	sock->sk->sk_state_change(sock->sk);
	return;
    }

    if (unlikely(events & SYS_SOCKET_ERR)) {
	if (events & (EPOLLHUP | EPOLLERR)) {
	    sock->sk->sk_state &= ~TCP_ESTABLISHED;
	}
	sock->sk->sk_state_change(sock->sk);
    }

    if (likely(events & SYS_SOCKET_RECV)) {
	if (unlikely(sock->sk->is_listener))
	    sock->sk->sk_state_change(sock->sk);
	else
	    sock->sk->sk_data_ready(sock->sk, 0);
    }
}

/******************************************************************************/
/* From net/core/skbuff.c */

/* Note that the current head of valid skb data is called "data" and it is the
 * start of the buffer they call "head".  But "tail" is the end of the data.
 */

void
kfree_skb(struct sk_buff *skb)
{
	if (unlikely(!skb))
	    return;
	if (!atomic_dec_and_test(&skb->users))
	    return;
	if (skb->head)
	    vfree(skb->head);
	record_free(skb);
}

struct sk_buff *
__alloc_skb(unsigned int size, gfp_t gfp_mask, int fclone, int node)
{
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	u8 *data;

	assert_eq(fclone, 0);

	skb = record_alloc(skb);

	size = SKB_DATA_ALIGN(size);
	data = vmalloc(size + sizeof(struct skb_shared_info));

	memset(skb, 0, offsetof(struct sk_buff, tail));
	skb->truesize = (int)(size + sizeof(struct sk_buff));
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + size;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
#endif

	//XXX needed?
	shinfo = skb_shinfo(skb);
	atomic_set(&shinfo->dataref, 1);
	shinfo->nr_frags  = 0;
	shinfo->gso_size = 0;
	shinfo->gso_segs = 0;
	shinfo->gso_type = 0;
	shinfo->ip6_frag_id = 0;
	shinfo->tx_flags.flags = 0;
	skb_frag_list_init(skb);
	memset(&shinfo->hwtstamps, 0, sizeof(shinfo->hwtstamps));

	return skb;
}

void 
skb_trim(struct sk_buff *skb, unsigned int len)
{
        if (skb->len > len)
                __skb_trim(skb, len);
}

/* Reserve the next len bytes of space in the skb and return pointer to it */
/* Here, _put() is not the inverse of _get() */
unsigned char *
skb_put(struct sk_buff *skb, unsigned int len)
{
        unsigned char *tmp = skb_tail_pointer(skb);
        skb->tail += len;
        skb->len  += len;
	verify_le(skb->tail, skb->end);
        return tmp;
}
