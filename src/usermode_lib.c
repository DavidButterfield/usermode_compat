/* usermode_lib.c
 * Partial implementation of compatibility for kernel code running in usermode
 * Copyright 2016 David A. Butterfield
 *
 * Most of the shim code is in usermode_lib.h
 */
#define NAME USERMODE_LIB
#include "usermode_lib.h"	/* kernel-code compatibility shim */

struct module __this_module = { .name = "SCST/DRBD", .arch = MODULE_ARCH_INIT, .version = "ZERO" };

_PER_THREAD struct task_struct * current;   /* current task (thread) structure */
extern _PER_THREAD char sys_pthread_name[16];

struct workqueue_struct * UMC_workq;

/* MTE (multi-threaded engine) will be our sys_service provider */
extern sys_service_handle_t MTE_sys_service_get(void);
extern void MTE_sys_service_put(void);

static struct task_struct UMC_init_current_space;

unsigned int nr_cpu_ids;

struct _irqthread * UMC_irqthread;   /* delivers "softirq" callbacks */

uint32_t crc32c_uniq;	//XXX hack makes these unique -- no good for matching

_PER_THREAD size_t UMC_size_t_JUNK = 0;	/* for avoiding unused-value gcc warnings */

LIST_HEAD(UMC_pagelist);
DEFINE_SPINLOCK(UMC_pagelist_lock);

LIST_HEAD(UMC_disk_list);
DEFINE_SPINLOCK(UMC_disk_list_lock);

struct timezone sys_tz;

DEFINE_RWLOCK(UMC_rcu_lock);

static struct socket * UMC_kernel_netlink_listener_sock;

struct net init_net = {
    .count          = ATOMIC_INIT(1),
    .dev_base_head  = LIST_HEAD_INIT(init_net.dev_base_head),
};

static __aligned(PAGE_SIZE) uint8_t empty_zero_page[PAGE_SIZE];
struct page zero_page;

static void
on_netlink_error(struct sock * sk)
{
    sys_notice("state change on netlink fd=%d", sk->fd);
}

#define NETLINK_BUFSIZE 8192

static void
on_netlink_recv(struct sock * sk, int len)
{
    assert_eq(sk->netlink_rcv, genl_rcv);
    expect_eq(len, 0);

    struct sk_buff * skb = alloc_skb(NETLINK_BUFSIZE, IGNORED);

    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t rc = recvfrom(sk->fd, skb->data, NETLINK_BUFSIZE, MSG_DONTWAIT,
			    &src_addr, &addrlen);

    if (rc <= 0) {
	if (rc == 0)
	    sys_notice("EOF on netlink fd=%d", sk->fd);
	else {
	    if (errno == EAGAIN) {
		sys_notice("EAGAIN on netlink fd=%d", sk->fd);
		return;
	    }
	    perror("netlink recv");
	    sys_warning("error on netlink fd=%d", sk->fd);
	}
	struct socket * sock = container_of(sk, struct socket, sk_s);   /* annoying */
	kfree_skb(skb);
	init_net.genl_sock = NULL;  //XXXXX

	sock_release(sock);
	return;
    }

    skb->len += rc;
    skb->tail += rc;
    skb->sk = sk;

    NETLINK_CB(skb).pid = ntohs(src_addr.sin_port);
    NETLINK_CB(skb).sk = sk;

    mutex_lock(sk->cb_mutex);
    sk->netlink_rcv(skb);
    mutex_unlock(sk->cb_mutex);
}

extern void UMC_genl_init(void);

/* Open a datagram socket for the kernel side of the simulated netlink */
static void
establish_netlink(void)
{
    if (init_net.genl_sock) {
	sys_warning("netlink listener already established!");
	return;
    }

    UMC_genl_init();

    struct sockaddr_in addr = {
	.sin_family = AF_INET,
	.sin_addr = { htonl(0x7f000001) },	//127.0.0.1
	.sin_port = htons(UMC_NETLINK_PORT),
	.sin_zero = { 0 }
    };

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	perror("UMC_init netlink: ");
	sys_warning("UMC_init could not open generic netlink");

    } else if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("UMC_init netlink bind: ");
	sys_warning("UMC_init could not bind generic netlink");
	close(fd);

    } else {
	sys_notice("starting netlink listener");

	struct file * file = _fget(fd);
	if (!file) {
	    sys_warning("could not allocate file for netlink listener");
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

/* A real signal */
static void
UMC_sig_handler(int signo)
{
    sys_notice("REAL SIGNAL %u (0x%lx) received by task %s (%d), pending: 0x%lx",
	    signo, 1L<<signo, current->comm, current->pid, current->signals_pending);
}

/* Setup for emulated inter-thread signals with a real signal */
static void
UMC_sig_setup(void)
{
    struct sigaction act = {
	.sa_handler = UMC_sig_handler
    };
    sigaction(UMC_SIGNAL, &act, NULL);
}

/* Is a fake signal pending for this thread? */
int
signal_pending(struct task_struct * task)
{
    if (!task->signals_pending)
	return false;
    sys_notice("signals pending tid=%u: 0x%lx", task->pid, task->signals_pending);
    return true;
}

/* Initialize the usermode_lib usermode compatibility module */
/* mountname is the path to the procfs or sysfs mount point */
error_t
UMC_init(char * mountname)
{
    /* Initialize a page of zeros for general use */
    struct page * page = &zero_page;
    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = 0;	/* single page */
    page_address(page) = empty_zero_page;
    spin_lock(&UMC_pagelist_lock);
    list_add(&page->UMC_page_list, &UMC_pagelist);
    spin_unlock(&UMC_pagelist_lock);

    /* Set up "current" for this initial thread --
     * Even though this isn't necessarily a (simulated) "kernel" thread (e.g. iscsi-scstd
     * issuing an ioctl), we still set up "current" for it because once the thread passes
     * through the ioctl interface it uses the "kernel" services which expect "current".
     */
    assert_eq(current, NULL);
    UMC_current_init(&UMC_init_current_space, sys_thread_current(),
		     (void *)UMC_init, NULL, sys_pthread_name);
    UMC_current_set(&UMC_init_current_space);

    {
	cpu_set_t mask;
	sched_getaffinity(current->pid/*tid*/, sizeof(mask), &mask);
	nr_cpu_ids = CPU_COUNT(&mask);
    }

    /* fuse forks, so do it before opening file descriptors */
    error_t err = UMC_fuse_start(mountname);
    expect_noerr(err, "UMC_fuse_start");

    UMC_irqthread = irqthread_run("UMC_irqthread");

    UMC_workq = create_workqueue("UMC_workq");

    sys_tz.tz_minuteswest = timezone/60;    /* see tzset(3) */
    sys_tz.tz_dsttime = daylight;	    /* see tzset(3) */

    establish_netlink();

    UMC_sig_setup();

    return E_OK;
}

void
UMC_exit(void)
{
    assert(current);
    error_t err;

    sock_release(UMC_kernel_netlink_listener_sock);
    UMC_kernel_netlink_listener_sock = NULL;

    err = UMC_fuse_stop();
    if (err == -EINVAL) { /* XXX Ignore for the SIGINT hack */ }
    else expect_noerr(err, "UMC_fuse_stop");

    err = UMC_fuse_exit();
    expect_noerr(err, "UMC_fuse_exit");

    flush_workqueue(UMC_workq);
    destroy_workqueue(UMC_workq);
    UMC_workq = NULL;

    if (UMC_irqthread->SYS != sys_thread_current()) {
	irqthread_stop(UMC_irqthread);
	irqthread_destroy(UMC_irqthread);
	UMC_irqthread = NULL;
    } else
	sys_warning("UMC_exit called on UMC_irqthread");

    /* Our caller does the pthread_exit */
}

/******************************************************************************/

/* kthread starts running on-thread */
error_t
UMC_kthread_fn(void * v_task)
{
    struct task_struct * task = v_task;
    UMC_current_set(task);

    pr_debug("Thread %s (%p, %u) starts task->SYS %s (%p) task %s (%p)\n",
	     sys_thread_name(sys_thread), sys_thread, gettid(),
	     sys_thread_name(task->SYS), task->SYS,
	     task->comm, task);

    /* Let our creating thread return from kthread_create() */
    complete(&task->started);

    /* completed by wake_up_process() */
    wait_for_completion(&task->start_release);

				      /*** Run the kthread logic ***/
    error_t ret = task->exit_code = task->run_fn(task->run_env);

    /* Let our stopping thread return from kthread_stop() */
    spin_lock(&task->stopped.wait.lock);
    complete(&task->stopped);
    spin_unlock(&task->stopped.wait.lock);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/

    return ret;
}

/* irqthread runs event_task on-thread */
error_t
UMC_irqthread_fn(void * v_irqthread)
{
    struct _irqthread * irqthread = v_irqthread;
    UMC_current_set(irqthread->current);

    complete(&irqthread->started);
    //XXX affinity?
    //XXX wait for start release?

    error_t ret = sys_event_task_run(irqthread->event_task);  /*** run the event_task logic ***/

    complete(&irqthread->stopped);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/
    return ret;
}

/* work queue thread starts running on-thread */
static error_t
_UMC_work_queue_thr(struct workqueue_struct * workq, char * wq_name)
{
    spin_lock(&workq->lock);
    assert_eq(current, workq->owner);

    while (!kthread_should_stop()) {

	/* Process each item on the workq one-by-one in the order queued */
	while (!list_empty_careful(&workq->list)) {
	    struct work_struct * work = list_first_entry(&workq->list, typeof(*work), entry);
	    list_del_init(&work->entry);
	    spin_unlock(&workq->lock);	    /* unlock workq while delivering callback */
	    {
		work->fn(work);		    /* callback to work function */
	    }
	    spin_lock(&workq->lock);
	}

	/* We have exhausted the workq */
	while (unlikely(atomic_read(&workq->is_flushing))) {
	    atomic_dec(&workq->is_flushing);
	    wake_up_one(&workq->flushed);
	}

	/* Announce we are sleepy so enqueuers will wake us up (we are holding the lock) */
	workq->is_idle = true;
	    /* wait_event_locked() may drop and retake workq->lock */
	wait_event_locked(workq->wake, !list_empty_careful(&workq->list)
						|| atomic_read(&workq->is_flushing) 
						|| kthread_should_stop(),
				       lock, workq->lock);
	workq->is_idle = false;
    }

    spin_unlock(&workq->lock);
    return E_OK;
}

error_t
UMC_work_queue_thr(void * v_workq)
{
    struct workqueue_struct * workq = v_workq;
    /* Put name of the queue somewhere visible in a gdb backtrace */
    return _UMC_work_queue_thr(workq, workq->name);
}

#ifdef UMC_TASKLETS

/* tasklet thread starts running on-thread */
static error_t
_UMC_tasklet_thr(struct tasklet_struct * tasklet, const char * tasklet_name)
{
    spin_lock(&tasklet->lock);
    assert_eq(current, tasklet->owner);

    while (!kthread_should_stop()) {

	while (tasklet->want_run) {
	    tasklet->want_run = false;
	    spin_unlock(&tasklet->lock);
	    tasklet->fn(tasklet->arg);
	    spin_lock(&tasklet->lock);
	}

	tasklet->is_idle = true;

	/* Timeout allows us to occasionally check for kthread_should_stop() */
	sys_time_t t_end = sys_time_now() + WAITQ_CHECK_INTERVAL;
	struct timespec const ts_end = {
		    .tv_sec = sys_time_delta_to_sec(t_end),
		    .tv_nsec = sys_time_delta_mod_sec(t_end)
	};

	pthread_cond_timedwait(&tasklet->pcond, &tasklet->lock.plock, &ts_end);
	tasklet->is_idle = false;
    }

    spin_unlock(&tasklet->lock);
    return E_OK;
}

/* Create a tasklet thread */
error_t
UMC_tasklet_thr(void * v_tasklet)
{
    struct tasklet_struct * tasklet = v_tasklet;
    /* Put name of the tasklet somewhere visible in a gdb backtrace */
    return _UMC_tasklet_thr(tasklet, tasklet->name);
}

#endif

/* Deliver system timer alarms to emulated kernel timer */
void
UMC_alarm_handler(void * const v_timer, uint64_t const now, error_t const err)
{
    assert_eq(err, E_OK);
    if (unlikely(err != E_OK)) return;

    struct timer_list * const timer = v_timer;
    //XXXXX expect(timer->alarm);   //XXX Bug when alarm goes off quickly

    //XXX A very recent call to mod_timer() may have updated the expire time
    // assert(time_after_eq(now, jiffies_to_sys_time(timer->expires)));
    assert(timer->function);
    timer->alarm = NULL;

    timer->function(timer->data);
		    /*** Note that timer may already no longer exist ***/
}

/* Process "delayed work" timeout events -- runs on UMC_event_task */
void
UMC_delayed_work_process(uintptr_t u_dwork)
{
    struct delayed_work * dwork = (void *)u_dwork;
    dwork->work.fn(&dwork->work);
}

/******************************************************************************/
/* The sock->ops point to these shim functions */

ssize_t
sock_no_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
    return UMC_kernelize64(send(sock->sk->fd, page_address(page) + offset, size, flags));
}

error_t
UMC_setsockopt(struct socket * sock, int level, int optname, void *optval, int optlen)
{
    error_t ret = UMC_kernelize(setsockopt(sock->sk->fd, level, optname, optval, optlen));
#if 0
    sys_notice("%s (%d) SETSOCKOPT fd=%d level=%d optname=%d optval=0x%x optlen=%d returns %d",
		current->comm, current->pid, sock->sk->fd,
		level, optname, *(int *)optval, optlen, ret);
#endif
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
	    return E_OK;
	}
    } else
	return UMC_kernelize(getsockname(sock->sk->fd, addr, addrlen));
}

/* Does not enable poll events or start a receive handler thread for the socket */
error_t
UMC_sock_connect(struct socket * sock, struct sockaddr * addr, socklen_t addrlen, int flags)
{
    //XXX flags ?
    struct sockaddr_in * inaddr = (struct sockaddr_in *)addr;
    sys_notice("%s (%d) connecting socket fd=%d to %d.%d.%d.%d port %u",
		current->comm, current->pid, sock->sk->fd,
		NIPQUAD(inaddr->sin_addr), inaddr->sin_port);

    error_t err = UMC_kernelize(connect(sock->sk->fd, addr, addrlen));
    if (!err) {
	sock->sk->sk_state = TCP_ESTABLISHED;
	UMC_sock_filladdrs(sock);
    }

    sys_notice("%s (%d) connected socket fd=%d to %d.%d.%d.%d port %u err=%d",
		current->comm, current->pid, sock->sk->fd,
		NIPQUAD(inaddr->sin_addr), inaddr->sin_port, err);
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
	    UMC_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));	//XXX
	}

	err = UMC_kernelize(bind(sock->sk->fd, addr, addrlen));
	if (err == E_OK) {
	    sys_notice("%s (%d) binds socket fd=%d to %d.%d.%d.%d port %u",
			current->comm, current->pid, sock->sk->fd,
			NIPQUAD(inaddr->sin_addr), inaddr->sin_port);
	    UMC_sock_filladdrs(sock);
	} else {
	    sys_warning("%s (%d) ERROR %d binding fd=%d to %d.%d.%d.%d port %u",
			current->comm, current->pid, sock->sk->fd,
			err, NIPQUAD(inaddr->sin_addr), inaddr->sin_port);
	}
    }

    return err;
}

error_t
UMC_sock_listen(struct socket * sock, int backlog)
{
    error_t ret = UMC_kernelize(listen(sock->sk->fd, backlog));
    if (ret != E_OK)
	return ret;

    if (sock->sk->sk_state_change == UMC_sock_cb_state)
	sys_warning("Listening on sockfd=%d with unset sk_state_change", sock->sk->fd);

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

    int newfd = UMC_kernelize(accept4(listener->sk->fd, &addr, &addrlen, flags));
    if (newfd < 0) {
	*newsock = NULL;
	sys_warning("Accept failed listenfd=%d err=%d", listener->sk->fd, newfd);
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

    (*newsock)->sk->sk_state_change = listener->sk->sk_state_change;	//XXX why?

    sys_notice("Accepted incoming socket connection listenfd=%d newfd=%d peer_port=%d",
		listener->sk->fd, newfd, ntohs((*newsock)->sk->sk_dport));

    return E_OK;
}

error_t
UMC_sock_shutdown(struct socket * sock, int k_how)
{
    int u_how;
    if ((k_how & RCV_SHUTDOWN) && (k_how & SEND_SHUTDOWN)) u_how = SHUT_RDWR;
    else if (k_how & RCV_SHUTDOWN) u_how = SHUT_RD;
    else if (k_how & SEND_SHUTDOWN) u_how = SHUT_WR;
    else {
	sys_warning("UMC_sock_shutdown called with bad flags 0x%x", k_how);
	u_how = SHUT_RDWR;
    }
    return shutdown(sock->sk->fd, u_how);
}

//XXXX What is the precise difference between disconnect and shutdown(RW)?
//XXX Where is the intended semantic of sk_prot->disconnect documented?
void
UMC_sock_discon(struct sock * sk, int XXX)
{
    struct socket * sock = container_of(sk, struct socket, sk_s);
    UMC_sock_shutdown(sock, SHUT_RDWR);
}

/* These are the original targets of the sk callbacks before the app intercepts them --
 * Because our event model here is EDGE TRIGGERED, we can get away with doing nothing
 */
void UMC_sock_cb_read(struct sock * sk, int obsolete)	{ sys_warning("fd=%d", sk->fd); }
void UMC_sock_cb_write(struct sock * sk)		{ sys_warning("fd=%d", sk->fd); }
void UMC_sock_cb_state(struct sock * sk)		{ sys_warning("fd=%d", sk->fd); }

/* Callback on event_task when socket fd ready, dispatches to XMIT and/or RECV sk callback */
void
UMC_sock_xmit_event(void * env, uintptr_t events, error_t err)
{
    struct socket * sock = env;
    if (unlikely(err != E_OK)) {
	sock->sk->sk_state_change(sock->sk);
	return;
    }

    if (unlikely(events & SYS_SOCKET_ERR)) {
	if (events & (EPOLLHUP | EPOLLERR)) {
	    sock->sk->sk_state &= ~TCP_ESTABLISHED;	//XXX right?
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
    if (unlikely(err != E_OK)) {
	sock->sk->sk_state_change(sock->sk);
	return;
    }

    if (unlikely(events & SYS_SOCKET_ERR)) {
	if (events & (EPOLLHUP | EPOLLERR)) {
	    sock->sk->sk_state &= ~TCP_ESTABLISHED;	//XXX right?
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

static void
blk_queue_release(struct kobject *kobj)
{
    struct request_queue * q = container_of(kobj, struct request_queue, kobj);
//  bdi_destroy(&q->backing_dev_info);
    record_free(q);
}

static struct attribute *default_blk_queue_attrs[] = { };

struct kobj_type blk_queue_ktype = {
//      .sysfs_ops      = &queue_sysfs_ops,
        .default_attrs  = default_blk_queue_attrs,
        .release        = blk_queue_release,
};

static void
device_release(struct kobject *kobj)
{
    struct device * dev = container_of(kobj, struct device, kobj);
    record_free(dev);
}

static struct attribute *default_device_attrs[] = { };

struct kobj_type device_ktype = {
//      .sysfs_ops      = &device_sysfs_ops,
        .default_attrs  = default_device_attrs,
        .release        = device_release,
};

/******************************************************************************/

#if 1
#undef READ_ONCE
#undef WRITE_ONCE
#define BP()				sys_breakpoint()
#define MEM_MASK(x)			((unsigned long)((typeof(x))(-1)) & 0xfffffffffffff000ul)
#define MEM_UNINIT(x)			(MEM_MASK(x) & MEM_PATTERN_ALLOC_64)
#define MEM_BAD(x)			(MEM_MASK(x) == MEM_UNINIT(x))
#define WRITE_ONCE(x, val)		((MEM_BAD(x) || ((x) && MEM_BAD(*(uintptr_t *)x)) || MEM_BAD(val)) ? BP() : (*_VOLATIZE(&(x)) = (val)))
#define READ_ONCE(x)			((MEM_BAD(x) || ((x) && MEM_BAD(*(uintptr_t *)x))) ? BP() : (*_VOLATIZE(&(x))))
#endif

struct rb_node *
rb_next(const struct rb_node *node)
{
        struct rb_node *parent;
        if (RB_EMPTY_NODE(node))
                return NULL;

        if (node->rb_right) {
                node = node->rb_right;
                while (node->rb_left)
                        node = node->rb_left;
                return _unconstify(node);
        }

        while ((parent = rb_parent(node)) && node == parent->rb_right)
                node = parent;

        return parent;
}

/* Replace an old (current) child of parent with a new one, in root's tree */
/* On return parent refers to the new child.  Child is not modified. */
static inline void
__rb_change_child(struct rb_node *old, struct rb_node *new,
                  struct rb_node *parent, struct rb_root *root)
{
        if (parent) {
		assert(old == parent->rb_left || old == parent->rb_right);
                if (parent->rb_left == old)
                        WRITE_ONCE(parent->rb_left, new);
		else if (parent->rb_right == old)
                        WRITE_ONCE(parent->rb_right, new);
                else
			sys_breakpoint();
        } else {
		assert(old == root->rb_node);
                WRITE_ONCE(root->rb_node, new);
	}
}

/* Remove node from root's tree.  Move node's successor into node's position */
void
rb_erase(struct rb_node * const node, struct rb_root * const root)
{
        struct rb_node * right = node->rb_right;
        struct rb_node * left = node->rb_left;
        struct rb_node * parent = rb_parent(node);
        if (!left) {
		/* No left child -- replace node with its right child, if any */
                if (right)
			rb_set_parent(right, parent);
                __rb_change_child(node, right, parent, root);
        }
	else if (!right) {
		/* No right child -- replace node with its left child */
                rb_set_parent(left, parent);
                __rb_change_child(node, left, parent, root);
        }
	else {	/* Node being removed has two children */
		/* Find successor, which will move to take over node's position in the tree */
		struct rb_node * successor = right;

		while (successor->rb_left) {
			parent = successor;
			successor = successor->rb_left;
		}

		if (successor != right) {
			/* successor is the left child of parent.
			 * successor has no left child; move successor's right child (if any)
			 * to replace successor as the new left child of successor's parent */
			WRITE_ONCE(parent->rb_left, successor->rb_right);
			if (parent->rb_left)
				rb_set_parent(parent->rb_left, parent);

			/* successor takes on node's right subtree as its own */
			WRITE_ONCE(successor->rb_right, node->rb_right);
			rb_set_parent(successor->rb_right, successor);
		}

		/* successor takes on node's left subtree as its own */
		WRITE_ONCE(successor->rb_left, node->rb_left);
		rb_set_parent(successor->rb_left, successor);

		/* successor takes node's parent as its own */
		rb_set_parent(successor, rb_parent(node));

		/* node's parent takes successor child as replacement for node */
		__rb_change_child(node, successor, rb_parent(node), root);
	}
}
