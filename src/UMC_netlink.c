/* UMC_netlink.c
 * Compatibility for kernel code running in usermode
 * Copyright 2016-2019 David A. Butterfield
 */
#define _GNU_SOURCE

#define  NO_UMC_SOCKETS	    // inhibit usermode_lib ucred for the one in sys/socket.h
#include <sys/socket.h>
#include </usr/include/asm-generic/socket.h> /* sys/socket.h included the wrong asm/socket.h */
#include "UMC_socket.h"	    // must be after sys/socket.h, when NO_UMC_SOCKETS
#include "UMC_netlink.h"

/* Import Hacked-up copy of UMC_genl.c */
#include "UMC_genl.c"	    //XXX

#define trace_netlink(fmtargs...)    //	nlprintk(fmtargs)

struct net init_net;

static void
on_netlink_error(struct sock * sk)
{
    trace_netlink("state change on netlink fd=%d", sk->fd);
}

#define NETLINK_BUFSIZE 8192

error_t
UMC_netlink_xmit(struct sock *sk, struct sk_buff *skb, uint32_t pid, uint32_t group, int nonblock)
{
    int flags = MSG_NOSIGNAL;
    // XXX there is no logic here to support xmit-ready callbacks, so always do synchronous
    // flags |= nonblock ? MSG_DONTWAIT : 0;

    struct sockaddr_in dst_addr = {
	.sin_family = AF_INET,
	.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
	.sin_port = htons((uint16_t)pid),
	.sin_zero = { 0 },
    };

    if (group) {
	if (group < 32) {
	    dst_addr.sin_addr.s_addr = htonl(224u<<24 | 0u<<16 | 0u<<8 | group);    //XXXX
	    dst_addr.sin_port = 7789;						    //XXXX
	} else
	    pr_warning("multicast group=%d out of range [1-31]\n", group);
    }

    ssize_t nsent = sendto(sk->fd, skb->data, skb->len, flags, &dst_addr, sizeof(dst_addr));

    if (nsent < 0) {
	error_t ret = (error_t)UMC_kernelize64(nsent);
	pr_warning("error %d sending on netlink fd=%d\n", ret, sk->fd);
	return ret;
    }
    assert_ge(nsent, 0);
    assert_le(nsent, UINT_MAX);

    skb->data += (unsigned)nsent;
    skb->len -= (unsigned)nsent;

    kfree_skb(skb);	/* drop one reference to the skb */

    return 0;
}

/* net/netlink/af_netlink.c */

static void
netlink_destroy_callback(struct netlink_callback *cb)
{
	kfree_skb(cb->skb);
	kfree(cb);
}

static int
netlink_dump(struct sock *sk)
{
	struct netlink_sock *nlk = nlk_sk(sk);
	struct netlink_callback *cb;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int len, err = -ENOBUFS;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		goto errout;
	skb->sk = sk;

	mutex_lock(nlk->cb_mutex);

	cb = nlk->cb;
	if (cb == NULL) {
		err = -EINVAL;
		goto errout_skb;
	}

	len = cb->dump(skb, cb);

#if 0	//XXX how do repeat calls of netlink_dump() happen in a real kernel?
	// Someone is supposed to call this function repeatedly...
	if (len > 0) {
		mutex_unlock(nlk->cb_mutex);
		netlink_unicast(sk, skb, NETLINK_CB(cb->skb).pid, 0);
		return 0;
	}
#else
	// ...but no one does, so do this instead for now.
	while (len > 0) {
		skb_get(skb);
		netlink_unicast(sk, skb, NETLINK_CB(cb->skb).pid, 0);
		len = cb->dump(skb, cb);
	}
#endif

	nlh = nlmsg_put_answer(skb, cb, NLMSG_DONE, sizeof(len), NLM_F_MULTI);
	if (!nlh)
		goto errout_skb;

	memcpy(nlmsg_data(nlh), &len, sizeof(len));

	netlink_unicast(sk, skb, NETLINK_CB(cb->skb).pid, 0);

	if (cb->done)
		cb->done(cb);
	nlk->cb = NULL;
	mutex_unlock(nlk->cb_mutex);

	netlink_destroy_callback(cb);
	return 0;

errout_skb:
	mutex_unlock(nlk->cb_mutex);
	kfree_skb(skb);
errout:
	return err;
}

int
netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
		       const struct nlmsghdr *nlh,
		       int (*dump)(struct sk_buff *skb,
				   struct netlink_callback *),
		       int (*done)(struct netlink_callback *))
{
	struct netlink_callback *cb;
	struct sock *sk;
	struct netlink_sock *nlk;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (cb == NULL)
		return -ENOBUFS;

	cb->dump = dump;
	cb->done = done;
	cb->nlh = nlh;
	atomic_inc(&skb->users);
	cb->skb = skb;

	sk = init_net.genl_sock;
	if (sk == NULL) {
		netlink_destroy_callback(cb);
		return -ECONNREFUSED;
	}
	nlk = nlk_sk(sk);
	/* A dump is in progress... */
	mutex_lock(nlk->cb_mutex);
	if (nlk->cb) {
		mutex_unlock(nlk->cb_mutex);
		netlink_destroy_callback(cb);
		return -EBUSY;
	}
	nlk->cb = cb;
	mutex_unlock(nlk->cb_mutex);

	netlink_dump(sk);

	/* We successfully started a dump, by returning -EINTR we
	 * signal not to send ACK even if it was requested.
	 */
	return -EINTR;
}

static void
on_netlink_recv(struct sock * sk, int len)
{
    expect_eq(len, 0);

    struct sk_buff * skb = alloc_skb(NETLINK_BUFSIZE, IGNORED);

    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t rc = UMC_kernelize64(recvfrom(sk->fd, skb_tail_pointer(skb),
			NETLINK_BUFSIZE, MSG_DONTWAIT, &src_addr, &addrlen));

    if (rc <= 0) {
	kfree_skb(skb);
	if (rc == 0) {
	    pr_warning("Zero-length datagram on netlink fd=%d\n", sk->fd);
	    return;
	} else if (errno == EAGAIN) {
	    pr_warning("EAGAIN on netlink fd=%d\n", sk->fd);
	    return;
	}
	pr_warning("error %ld on netlink fd=%d\n", rc, sk->fd);

	struct socket * sock = container_of(sk, struct socket, sk_s);
	init_net.genl_sock = NULL;
	sock_release(sock);

	//XXXX Should re-establish netlink service socket

	return;
    }
    assert_ge(rc, 0);
    assert_le(rc, UINT_MAX);

    skb->len += (unsigned)rc;
    skb->tail += (unsigned)rc;
    verify_le(skb->tail, skb->end);

    skb->sk = sk;
    NETLINK_CB(skb).pid = ntohs(src_addr.sin_port);

    sk->netlink_rcv(skb);

    kfree_skb(skb);
}

/* Open a datagram socket for the kernel side of the simulated netlink */
void
netlink_init(void)
{
    if (init_net.genl_sock) {
	pr_warning("netlink server already established!\n");
	return;
    }

    UMC_genl_init();

    struct sockaddr_in addr = {
	.sin_family = AF_INET,
	.sin_addr = { htonl(0x7f000001) },	/* 127.0.0.1 */
	.sin_port = htons(UMC_NETLINK_PORT),
	.sin_zero = { 0 }
    };

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	pr_warning("UMC_init could not open generic netlink: %s\n", strerror(errno));

    } else if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	pr_warning("UMC_init could not bind generic netlink: %s\n", strerror(errno));
	close(fd);

    } else {
	pr_notice("starting netlink server fd=%d\n", fd);

	struct file * file = _fget(fd);
	if (!file) {
	    pr_warning("could not allocate file for netlink socket\n");
	    close(fd);
	    return;
	}

	struct socket * sock = SOCKET_I(file->inode);
	struct sock * sk = sock->sk;
	sk->sk = sk;	/* self-reference: our netlink sock fields live in sk */
	sk->cb_mutex = &sk->cb_def_mutex;
	mutex_init(sk->cb_mutex);
	sk->netlink_rcv = genl_rcv; /* where kernel code wants incoming nl msgs */
	sk->sk_user_data = sk;

	/* Fill in the ipaddr/port in the socket structure from the real socket */
	UMC_sock_filladdrs(sock);

	/* This is where kernel code likes to find its netlink sk */
	init_net.genl_sock = sk;

	/* Enable event polling and start the receive thread */
	UMC_sock_poll_start(sock, on_netlink_recv, NULL, on_netlink_error, "netlink_recv");
    }
}

void
netlink_exit(void)
{
    struct sock * sk = init_net.genl_sock;
    if (!sk) {
	pr_warning("netlink server not established!\n");
	return;
    }
    pr_notice("CLOSE netlink fd=%d\n", sk->fd);

    sock_release(sock_of_sk(sk));
    init_net.genl_sock = NULL;
}

