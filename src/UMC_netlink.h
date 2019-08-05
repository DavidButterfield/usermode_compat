/* UMC_netlink.h -- usermode compatibility for netlink
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * Netlink (implemented as UDP/IPv4)
 */
#ifndef UMC_NETLINK_H
#define UMC_NETLINK_H
#include "UMC_sys.h"
#include "UMC_socket.h"

extern void netlink_init(void);
extern void netlink_exit(void);

#define netlink_sock			sock
#define nlk_sk(sk)			(sk)

typedef struct kernel_cap_struct { } kernel_cap_t;

extern void UMC_genl_init(void);

extern void genl_rcv(struct sk_buff *skb);

struct notifier_block;
#include <linux/netlink.h>

#define UMC_NETLINK_PORT 1234u	/* UDP port for simulated netlink */

struct sk_buff;
extern error_t UMC_netlink_xmit(struct sock *sk, struct sk_buff *skb, u32 pid, u32 group, int nonblock);

#define netlink_unicast(sk, skb, pid, nonblock) \
    UMC_netlink_xmit((sk), (skb), (pid), 0, (nonblock))

#define netlink_broadcast(sk, skb, pid, group, flags) \
    UMC_netlink_xmit((sk), (skb), (pid), (group), 0)

#define read_pnet(pnet)			    (&init_net)
#define write_pnet(pnet, x)		    DO_NOTHING()
#define nl_dump_check_consistent(cb, nlh)   DO_NOTHING()
#define netlink_set_err(ssk, portid, group, code)   0	    //XXX
#define netlink_has_listeners(sk, group)	    true    //XXX

struct netlink_ext_ack
{
    const struct nlattr *bad_attr;
};

typedef struct { }			possible_net_t;

struct net {
    struct sock			      * genl_sock;
};

extern struct net init_net;

#define GENL_HDRLEN			NLMSG_ALIGN(sizeof(struct genlmsghdr))
#define GENL_NAMSIZ			16
#define GENL_ADMIN_PERM			0x01
#define SLAB_PANIC			0x00040000UL
struct genl_family;
#include <net/genetlink.h>

#endif /* UMC_NETLINK_H */
