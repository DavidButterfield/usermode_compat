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

    sys_notice("calling netlink handler skb=%p buf=%p len=%u", skb, skb->head, skb->len);

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

/* A real SIGHUP */
static void
sighup_handler(int signo)
{
    sys_notice("REAL SIGNAL %u (0x%lx) received by task %s (%d), pending: 0x%lx",
	    signo, 1L<<signo, current->comm, current->pid, current->signals_pending);
}

/* Setup for inter-thread signals with a real SIGHUP */
static void
sighup_setup(void)
{
    struct sigaction act = {
	.sa_handler = sighup_handler
    };
    sigaction(SIGHUP, &act, NULL);
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

    sighup_setup();

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

    /* Let our creating thread return from kthread_start */
    complete(&task->started);

    if (current->affinity_is_set) {
	sched_setaffinity(current->pid/*tid*/,
			  sizeof(current->cpus_allowed), (cpu_set_t *)&current->cpus_allowed);
    }

    wait_for_completion(&task->start_release);

				      /*** Run the kthread logic ***/
    error_t ret = task->exit_code = task->run_fn(task->run_env);

    /* Let our stopping thread return from kthread_stop() */
    //XXXXX take task lock
    complete(&task->stopped);
    //XXXXX drop task lock
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
	while (!list_empty(&workq->list)) {
	    struct work_struct * work = list_first_entry(&workq->list, typeof(*work), entry);
	    list_del(&work->entry);
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
	wait_event_locked(workq->wake, !list_empty(&workq->list)
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

int
autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key)
{
    int ret = true;
    sys_warning("XXXXX autoremove_wake_function wants to call default_wake_function");
#ifdef XXXXX
    wake_up(wq_entry);	//XXXXX ?
    ret = default_wake_function(wq_entry, mode, sync, key);
    if (ret)
#endif
         list_del_init(&wq_entry->entry);
    return ret;
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
    return UMC_kernelize(setsockopt(sock->sk->fd, level, optname, optval, optlen));
}

error_t
UMC_sock_getname(struct socket * sock, struct sockaddr * addr, socklen_t * addrlen, int peer)
{
    if (peer)
	return UMC_kernelize(getpeername(sock->sk->fd, addr, addrlen));
    else
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
	    UMC_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
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
UMC_sock_accept(struct socket * sock, struct socket ** newsock, int flags)
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    assert(sock->sk->is_listener);

    int fd = UMC_kernelize(accept4(sock->sk->fd, &addr, &addrlen, flags));
    if (fd < 0) {
	*newsock = NULL;
	sys_warning("Accept failed listenfd=%d err=%d", sock->sk->fd, fd);
	return fd;  /* -errno */
    }

    /* Wrap a file/inode/sock/sk around the fd we just accepted */
    struct file * file = _fget(fd);
    if (!file) {
	close(fd);
	return -ENOMEM;
    }

    *newsock = SOCKET_I(file->inode);
    assert_eq((*newsock)->sk->fd, fd);

    UMC_sock_filladdrs(*newsock);	/* get the local and peer addresses */
    sock->sk->sk_state = TCP_ESTABLISHED;

    sys_notice("Accepted incoming socket connection listenfd=%d newfd=%d",
		sock->sk->fd, fd);	//XXX

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
