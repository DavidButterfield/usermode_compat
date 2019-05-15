#include "usermode_lib.h"
#define MC 0

/* Lifted from 2.6.32 kernel net/netlink/genetlink.c */

static DEFINE_MUTEX(genl_mutex); /* serialization of message processing */

static inline void genl_lock(void)
{
	mutex_lock(&genl_mutex);
}

static inline void genl_unlock(void)
{
	mutex_unlock(&genl_mutex);
}

#define GENL_FAM_TAB_SIZE	16
#define GENL_FAM_TAB_MASK	(GENL_FAM_TAB_SIZE - 1)

static struct list_head family_ht[GENL_FAM_TAB_SIZE];

void UMC_genl_init(void);
void
UMC_genl_init(void)
{
    int i;
    for (i = 0; i < GENL_FAM_TAB_SIZE; i++)
	INIT_LIST_HEAD(&family_ht[i]);
}

#if MC
/*
 * Bitmap of multicast groups that are currently in use.
 *
 * To avoid an allocation at boot of just one unsigned long,
 * declare it global instead.
 * Bit 0 is marked as already used since group 0 is invalid.
 */
static unsigned long mc_group_start = 0x1;
static unsigned long *mc_groups = &mc_group_start;
static unsigned long mc_groups_longs = 1;
#endif

#define genl_ctrl_event(ctrl, arg)  /* */
//XXX static int genl_ctrl_event(int event, void *data);

static inline unsigned int genl_family_hash(unsigned int id)
{
	return id & GENL_FAM_TAB_MASK;
}

static inline struct list_head *genl_family_chain(unsigned int id)
{
	return &family_ht[genl_family_hash(id)];
}

static struct genl_family *genl_family_find_byid(unsigned int id)
{
	struct genl_family *f;

	list_for_each_entry(f, genl_family_chain(id), family_list)
		if (f->id == id)
			return f;

	return NULL;
}

static struct genl_family *genl_family_find_byname(char *name)
{
	struct genl_family *f;
	int i;

	for (i = 0; i < GENL_FAM_TAB_SIZE; i++)
		list_for_each_entry(f, genl_family_chain(i), family_list)
			if (strcmp(f->name, name) == 0)
				return f;

	return NULL;
}

static struct genl_ops *genl_get_cmd(u8 cmd, struct genl_family *family)
{
	struct genl_ops *ops;

	list_for_each_entry(ops, &family->ops_list, ops_list)
		if (ops->cmd == cmd)
			return ops;

	return NULL;
}

/* Of course we are going to have problems once we hit
 * 2^16 alive types, but that can only happen by year 2K
*/
static inline u16 genl_generate_id(void)
{
	static u16 id_gen_idx;
	int overflowed = 0;

	do {
		if (id_gen_idx == 0)
			id_gen_idx = GENL_MIN_ID;

		if (++id_gen_idx > GENL_MAX_ID) {
			if (!overflowed) {
				overflowed = 1;
				id_gen_idx = 0;
				continue;
			} else
				return 0;
		}

	} while (genl_family_find_byid(id_gen_idx));

	return id_gen_idx;
}

#if MC
static struct genl_multicast_group notify_grp;
#endif

/**
 * genl_register_mc_group - register a multicast group
 *
 * Registers the specified multicast group and notifies userspace
 * about the new group.
 *
 * Returns 0 on success or a negative error code.
 *
 * @family: The generic netlink family the group shall be registered for.
 * @grp: The group to register, must have a name.
 */
int genl_register_mc_group(struct genl_family *family,
			   struct genl_multicast_group *grp)
{
#if MC
	int id;
	unsigned long *new_groups;
	int err = 0;

	BUG_ON(grp->name[0] == '\0');

	genl_lock();

	/* special-case our own group */
	if (grp == &notify_grp)
		id = GENL_ID_CTRL;
	else
		id = find_first_zero_bit(mc_groups,
					 mc_groups_longs * BITS_PER_LONG);


	if (id >= mc_groups_longs * BITS_PER_LONG) {
		size_t nlen = (mc_groups_longs + 1) * sizeof(unsigned long);

		if (mc_groups == &mc_group_start) {
			new_groups = kzalloc(nlen, GFP_KERNEL);
			if (!new_groups) {
				err = -ENOMEM;
				goto out;
			}
			mc_groups = new_groups;
			*mc_groups = mc_group_start;
		} else {
			new_groups = krealloc(mc_groups, nlen, GFP_KERNEL);
			if (!new_groups) {
				err = -ENOMEM;
				goto out;
			}
			mc_groups = new_groups;
			mc_groups[mc_groups_longs] = 0;
		}
		mc_groups_longs++;
	}

	if (family->netnsok) {
		struct net *net;

		netlink_table_grab();
		rcu_read_lock();
		for_each_net_rcu(net) {
			err = __netlink_change_ngroups(net->genl_sock,
					mc_groups_longs * BITS_PER_LONG);
			if (err) {
				/*
				 * No need to roll back, can only fail if
				 * memory allocation fails and then the
				 * number of _possible_ groups has been
				 * increased on some sockets which is ok.
				 */
				rcu_read_unlock();
				netlink_table_ungrab();
				goto out;
			}
		}
		rcu_read_unlock();
		netlink_table_ungrab();
	} else {
		err = netlink_change_ngroups(init_net.genl_sock,
					     mc_groups_longs * BITS_PER_LONG);
		if (err)
			goto out;
	}

	grp->id = id;
	set_bit(id, mc_groups);
	list_add_tail(&grp->list, &family->mcast_groups);
	grp->family = family;

	genl_ctrl_event(CTRL_CMD_NEWMCAST_GRP, grp);
 out:
	genl_unlock();
	return err;
#else
	return 0;
#endif
}
EXPORT_SYMBOL(genl_register_mc_group);

#if MC
static void __genl_unregister_mc_group(struct genl_family *family,
				       struct genl_multicast_group *grp)
{
	struct net *net;
	BUG_ON(grp->family != family);

	netlink_table_grab();
	rcu_read_lock();
	for_each_net_rcu(net)
		__netlink_clear_multicast_users(net->genl_sock, grp->id);
	rcu_read_unlock();
	netlink_table_ungrab();

	clear_bit(grp->id, mc_groups);
	list_del(&grp->list);
	genl_ctrl_event(CTRL_CMD_DELMCAST_GRP, grp);
	grp->id = 0;
	grp->family = NULL;
}

/**
 * genl_unregister_mc_group - unregister a multicast group
 *
 * Unregisters the specified multicast group and notifies userspace
 * about it. All current listeners on the group are removed.
 *
 * Note: It is not necessary to unregister all multicast groups before
 *       unregistering the family, unregistering the family will cause
 *       all assigned multicast groups to be unregistered automatically.
 *
 * @family: Generic netlink family the group belongs to.
 * @grp: The group to unregister, must have been registered successfully
 *	 previously.
 */
void genl_unregister_mc_group(struct genl_family *family,
			      struct genl_multicast_group *grp)
{
	genl_lock();
	__genl_unregister_mc_group(family, grp);
	genl_unlock();
}
EXPORT_SYMBOL(genl_unregister_mc_group);
#endif

static void genl_unregister_mc_groups(struct genl_family *family)
{
#if MC
	struct genl_multicast_group *grp, *tmp;

	list_for_each_entry_safe(grp, tmp, &family->mcast_groups, list)
		__genl_unregister_mc_group(family, grp);
#endif
}

/**
 * genl_register_ops - register generic netlink operations
 * @family: generic netlink family
 * @ops: operations to be registered
 *
 * Registers the specified operations and assigns them to the specified
 * family. Either a doit or dumpit callback must be specified or the
 * operation will fail. Only one operation structure per command
 * identifier may be registered.
 *
 * See include/net/genetlink.h for more documenation on the operations
 * structure.
 *
 * Returns 0 on success or a negative error code.
 */
int genl_register_ops(struct genl_family *family, struct genl_ops *ops)
{
	int err = -EINVAL;

	if (ops->dumpit == NULL && ops->doit == NULL)
		goto errout;

	if (genl_get_cmd(ops->cmd, family)) {
		err = -EEXIST;
		goto errout;
	}

	if (ops->dumpit)
		ops->flags |= GENL_CMD_CAP_DUMP;
	if (ops->doit)
		ops->flags |= GENL_CMD_CAP_DO;
	if (ops->policy)
		ops->flags |= GENL_CMD_CAP_HASPOL;

	genl_lock();
	list_add_tail(&ops->ops_list, &family->ops_list);
	genl_unlock();

	genl_ctrl_event(CTRL_CMD_NEWOPS, ops);
	err = 0;
errout:
	return err;
}

/**
 * genl_unregister_ops - unregister generic netlink operations
 * @family: generic netlink family
 * @ops: operations to be unregistered
 *
 * Unregisters the specified operations and unassigns them from the
 * specified family. The operation blocks until the current message
 * processing has finished and doesn't start again until the
 * unregister process has finished.
 *
 * Note: It is not necessary to unregister all operations before
 *       unregistering the family, unregistering the family will cause
 *       all assigned operations to be unregistered automatically.
 *
 * Returns 0 on success or a negative error code.
 */
int genl_unregister_ops(struct genl_family *family, struct genl_ops *ops)
{
	struct genl_ops *rc;

	genl_lock();
	list_for_each_entry(rc, &family->ops_list, ops_list) {
		if (rc == ops) {
			list_del(&ops->ops_list);
			genl_unlock();
			genl_ctrl_event(CTRL_CMD_DELOPS, ops);
			return 0;
		}
	}
	genl_unlock();

	return -ENOENT;
}

/**
 * genl_register_family - register a generic netlink family
 * @family: generic netlink family
 *
 * Registers the specified family after validating it first. Only one
 * family may be registered with the same family name or identifier.
 * The family id may equal GENL_ID_GENERATE causing an unique id to
 * be automatically generated and assigned.
 *
 * Return 0 on success or a negative error code.
 */
int genl_register_family(struct genl_family *family)
{
	int err = -EINVAL;

	if (family->id && family->id < GENL_MIN_ID)
		goto errout;

	if (family->id > GENL_MAX_ID)
		goto errout;

	INIT_LIST_HEAD(&family->ops_list);
	INIT_LIST_HEAD(&family->mcast_groups);

	genl_lock();

	if (genl_family_find_byname(family->name)) {
		err = -EEXIST;
		goto errout_locked;
	}

	if (genl_family_find_byid(family->id)) {
		err = -EEXIST;
		goto errout_locked;
	}

	if (family->id == GENL_ID_GENERATE) {
		u16 newid = genl_generate_id();

		if (!newid) {
			err = -ENOMEM;
			goto errout_locked;
		}

		sys_notice("assigned %d as netlink family->id", newid);
		family->id = newid;
	}

	if (family->maxattr) {
		family->attrbuf = kmalloc((family->maxattr+1) *
					sizeof(struct nlattr *), GFP_KERNEL);
		if (family->attrbuf == NULL) {
			err = -ENOMEM;
			goto errout_locked;
		}
	} else
		family->attrbuf = NULL;

	list_add_tail(&family->family_list, genl_family_chain(family->id));
	genl_unlock();

	genl_ctrl_event(CTRL_CMD_NEWFAMILY, family);

	return 0;

errout_locked:
	genl_unlock();
errout:
	return err;
}

/**
 * genl_register_family_with_ops - register a generic netlink family
 * @family: generic netlink family
 * @ops: operations to be registered
 * @n_ops: number of elements to register
 *
 * Registers the specified family and operations from the specified table.
 * Only one family may be registered with the same family name or identifier.
 *
 * The family id may equal GENL_ID_GENERATE causing an unique id to
 * be automatically generated and assigned.
 *
 * Either a doit or dumpit callback must be specified for every registered
 * operation or the function will fail. Only one operation structure per
 * command identifier may be registered.
 *
 * See include/net/genetlink.h for more documenation on the operations
 * structure.
 *
 * This is equivalent to calling genl_register_family() followed by
 * genl_register_ops() for every operation entry in the table taking
 * care to unregister the family on error path.
 *
 * Return 0 on success or a negative error code.
 */
int genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops)
{
	int err, i;

	err = genl_register_family(family);
	if (err)
		return err;

	for (i = 0; i < (int)n_ops; ++i, ++ops) {
		err = genl_register_ops(family, ops);
		if (err)
			goto err_out;
	}
	return 0;
err_out:
	genl_unregister_family(family);
	return err;
}
EXPORT_SYMBOL(genl_register_family_with_ops);

/**
 * genl_unregister_family - unregister generic netlink family
 * @family: generic netlink family
 *
 * Unregisters the specified family.
 *
 * Returns 0 on success or a negative error code.
 */
int genl_unregister_family(struct genl_family *family)
{
	struct genl_family *rc;

	genl_lock();

	genl_unregister_mc_groups(family);

	list_for_each_entry(rc, genl_family_chain(family->id), family_list) {
		if (family->id != rc->id || strcmp(rc->name, family->name))
			continue;

		list_del(&rc->family_list);
		INIT_LIST_HEAD(&family->ops_list);
		genl_unlock();

		kfree(family->attrbuf);
		genl_ctrl_event(CTRL_CMD_DELFAMILY, family);
		return 0;
	}

	genl_unlock();

	return -ENOENT;
}

/******************************************************************************/

#define nlk_sk(sk)  (sk)

static int netlink_dump(struct sock *sk)
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

	cb = nlk->cb;
	if (cb == NULL) {
		err = -EINVAL;
		goto errout_skb;
	}

	while (true) {
	    len = cb->dump(skb, cb);
	    sys_notice("cb->dump returns %d", len);
	    if (len <= 0)
		break;
	    netlink_unicast(sk, skb, 0/*pid_ignored*/, 0);
	}

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			    NLMSG_DONE, sizeof(len), NLM_F_MULTI);
	if (!nlh)
		goto errout_skb;

	usleep(1000*1000);	    //XXXXXX

	memcpy(nlmsg_data(nlh), &len, sizeof(len));
	netlink_unicast(sk, skb, 0/*pid_ignored*/, 0);

	if (cb->done) {
		sys_notice("call cb->done");
		cb->done(cb);
	}
	nlk->cb = NULL;

	kfree(cb);
	return 0;

errout_skb:
	kfree_skb(skb);
errout:
	return err;
}

static int
netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
		       struct nlmsghdr *nlh,
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
	cb->skb = skb;

	sk = init_net.genl_sock;
	if (sk == NULL) {
		kfree(cb);
		return -ECONNREFUSED;
	}
	nlk = nlk_sk(sk);

	nlk->cb = cb;

	netlink_dump(sk);

	/* We successfully started a dump, by returning -EINTR we
	 * signal not to send ACK even if it was requested.
	 */
	return -EINTR;
}

/******************************************************************************/

static int genl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct genl_ops *ops;
	struct genl_family *family;
	//struct net *net = sock_net(skb->sk);
	struct genl_info info;
	struct genlmsghdr *hdr = nlmsg_data(nlh);
	int hdrlen, err;

	family = genl_family_find_byid(nlh->nlmsg_type);
	if (family == NULL)
		return -ENOENT;

#if 0
	/* this family doesn't exist in this netns */
	if (!family->netnsok && !net_eq(net, &init_net))
		return -ENOENT;
#endif

	hdrlen = GENL_HDRLEN + family->hdrsize;
	if (nlh->nlmsg_len < nlmsg_msg_size(hdrlen))
		return -EINVAL;

	ops = genl_get_cmd(hdr->cmd, family);
	if (ops == NULL)
		return -EOPNOTSUPP;

#if 0
	if ((ops->flags & GENL_ADMIN_PERM) &&
	    security_netlink_recv(skb, CAP_NET_ADMIN))
		return -EPERM;
#endif

	if (nlh->nlmsg_flags & NLM_F_DUMP) {
		if (ops->dumpit == NULL)
			return -EOPNOTSUPP;

		genl_unlock();
		sys_notice("netlink_dump_start");
		err = netlink_dump_start(init_net.genl_sock, skb, nlh,
					 ops->dumpit, ops->done);
		genl_lock();
		return err;
	}

	if (ops->doit == NULL)
		return -EOPNOTSUPP;

	if (family->attrbuf) {
		err = nlmsg_parse(nlh, hdrlen, family->attrbuf, family->maxattr,
				  ops->policy);
		if (err < 0)
			return err;
	}

	info.snd_seq = nlh->nlmsg_seq;
	info.snd_pid = NETLINK_CB(skb).pid;
	info.nlhdr = nlh;
	info.genlhdr = nlmsg_data(nlh);
	info.userhdr = nlmsg_data(nlh) + GENL_HDRLEN;
	info.attrs = family->attrbuf;
	// genl_info_net_set(&info, net);

	sys_notice("doit");
	return ops->doit(skb, &info);
}

static
void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err)
{
	struct sk_buff *skb;
	struct nlmsghdr *rep;
	struct nlmsgerr *errmsg;
	size_t payload = sizeof(*errmsg);

	/* error messages get the original request appened */
	if (err)
		payload += nlmsg_len(nlh);

	skb = nlmsg_new(payload, GFP_KERNEL);
	assert(skb);

	rep = __nlmsg_put(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
			  NLMSG_ERROR, payload, 0);
	errmsg = nlmsg_data(rep);
	errmsg->error = err;
	memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(*nlh));
	netlink_unicast(in_skb->sk, skb, NETLINK_CB(in_skb).pid, MSG_DONTWAIT);
}

static inline unsigned char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len -= len;
//	BUG_ON(skb->len < skb->data_len);
	return skb->data += len;
}

static unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	return unlikely(len > skb->len) ? NULL : __skb_pull(skb, len);
}

int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *, struct nlmsghdr *))
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		unsigned int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
			goto ack;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto ack;

		err = cb(skb, nlh);
		if (err == -EINTR)
			goto skip;

ack:
		if (nlh->nlmsg_flags & NLM_F_ACK || err)
			netlink_ack(skb, nlh, err);

skip:
		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len)
			msglen = skb->len;
		skb_pull(skb, msglen);
	}

	return 0;
}

void genl_rcv(struct sk_buff *skb)
{
	genl_lock();
	netlink_rcv_skb(skb, &genl_rcv_msg);
	genl_unlock();
}
