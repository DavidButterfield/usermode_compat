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
    sys_notice("error on netlink socket");
}

static void
on_netlink_recv(struct sock * sk, int len)
{
    expect_eq(len, 0);
    char buf[8192];
    errno = 0;
    ssize_t rc = recv(sk->fd, buf, sizeof(buf), MSG_DONTWAIT);
    sys_notice("received netlink message, rc=%ld, errno=%d", rc, errno);
    if (rc > 0)
	mem_dump((uintptr_t)buf, (uintptr_t)buf+rc, __func__);
}

static void
on_netlink_incoming(struct sock * sk)
{
    struct socket * sock = container_of(sk, struct socket, sk_s);   /* annoying */
    struct socket * newsock;
    sys_notice("received incoming netlink connection");

    /* Intercept receive events */
    sock->sk->sk_user_data = sk;
    sock->sk->sk_data_ready = on_netlink_recv;
    sock->sk->sk_state_change = on_netlink_error;

    error_t err = UMC_sock_accept(sock, &newsock, 0);
    if (err) {
	sys_warning("dropped incoming netlink connection");
    } else {
	sys_notice("accepted incoming netlink connection");
    }
}

static void
on_netlink_incoming2(struct sock * sk, int ignored)
{
    on_netlink_incoming(sk);
}

static void
establish_netlink(void)
{
    if (UMC_kernel_netlink_listener_sock) {
	sys_warning("netlink listener already established!");
	return;
    }

    struct sockaddr_in addr = {
	.sin_family = AF_INET,
	// .sin_addr = { htonl(0x7f000001) },	//127.0.0.1
	.sin_port = htons(1234),
    };

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
	perror("UMC_init netlink socket: ");
	sys_warning("UMC_init could not open generic netlink socket");

    } else if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("UMC_init netlink bind: ");
	sys_warning("UMC_init could not bind generic netlink socket");
	close(fd);

    } else if (listen(fd, 16) < 0) {
	perror("UMC_init netlink listen: ");
	sys_warning("UMC_init could not listen on netlink");
	close(fd);

    } else {
	sys_notice("starting netlink listener");
	/* fget() starts the connection handler thread for the listener */
	struct file * file = fget(fd);
	if (!file) {
	    sys_warning("could not allocate file for netlink listener");
	    close(fd);
	    return;
	}

	UMC_kernel_netlink_listener_sock = SOCKET_I(file->inode);

	/* Intercept incoming-socket-ready events */
	UMC_kernel_netlink_listener_sock->sk->sk_user_data = UMC_kernel_netlink_listener_sock->sk;
	UMC_kernel_netlink_listener_sock->sk->sk_state_change = on_netlink_incoming;
	UMC_kernel_netlink_listener_sock->sk->sk_data_ready = on_netlink_incoming2;
    }
}

/* Initialize the usermode_lib usermode compatibility module */
/* mountname is the path to the procfs or sysfs mount point */
errno_t
UMC_init(char * mountname)
{
    page_init(&zero_page, 0);
    zero_page.vaddr = empty_zero_page;

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

    UMC_irqthread = irqthread_run("UMC_irqthread");

    errno_t err = UMC_fuse_start(mountname);
    expect_noerr(err, "UMC_fuse_start");

    UMC_workq = create_workqueue("UMC_workq");

    sys_tz.tz_minuteswest = timezone/60;    /* see tzset(3) */
    sys_tz.tz_dsttime = daylight;	    /* see tzset(3) */

    establish_netlink();

    return E_OK;
}

void
UMC_exit(void)
{
    assert(current);
    errno_t err;

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
errno_t
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
    errno_t ret = task->exit_code = task->run_fn(task->run_env);

    /* Let our stopping thread return from kthread_stop() */
    complete(&task->stopped);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/

    return ret;
}

/* irqthread runs event_task on-thread */
errno_t
UMC_irqthread_fn(void * v_irqthread)
{
    struct _irqthread * irqthread = v_irqthread;
    UMC_current_set(irqthread->current);

    complete(&irqthread->started);
    //XXX affinity?
    //XXX wait for start release?

    errno_t ret = sys_event_task_run(irqthread->event_task);  /*** run the event_task logic ***/

    complete(&irqthread->stopped);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/
    return ret;
}

/* work queue thread starts running on-thread */
static errno_t
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

errno_t
UMC_work_queue_thr(void * v_workq)
{
    struct workqueue_struct * workq = v_workq;
    /* Put name of the queue somewhere visible in a gdb backtrace */
    return _UMC_work_queue_thr(workq, workq->name);
}

/* tasklet thread starts running on-thread */
static errno_t
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
errno_t
UMC_tasklet_thr(void * v_tasklet)
{
    struct tasklet_struct * tasklet = v_tasklet;
    /* Put name of the tasklet somewhere visible in a gdb backtrace */
    return _UMC_tasklet_thr(tasklet, tasklet->name);
}

/* Deliver system timer alarms to emulated kernel timer */
void
UMC_alarm_handler(void * const v_timer, uint64_t const now, errno_t const err)
{
    assert_eq(err, E_OK);
    if (unlikely(err != E_OK)) return;

    struct timer_list * const timer = v_timer;
    assert(timer->alarm);
    assert(time_after_eq(now, jiffies_to_sys_time(timer->expires)));
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
    return UMC_kernelize64(send((sock)->sk->fd, page_address(page) + (offset), (size), (flags)));
}

errno_t
UMC_setsockopt(struct socket * sock, int level, int optname, void *optval, int optlen)
{
    return UMC_kernelize(setsockopt(sock->sk->fd, level, optname, optval, optlen));
}

errno_t
UMC_sock_connect(struct socket * sock, struct sockaddr * addr, socklen_t addrlen)
{
    return UMC_kernelize(connect(sock->sk->fd, addr, addrlen));
}

errno_t
UMC_sock_bind(struct socket * sock, struct sockaddr *addr, socklen_t addrlen)
{
    return UMC_kernelize(bind(sock->sk->fd, addr, addrlen));
}

errno_t
UMC_sock_listen(struct socket * sock, int backlog)
{
    return UMC_kernelize(listen(sock->sk->fd, backlog));
}

//XXXXXX need to be able to intercept receives before enabling them in fget
errno_t
UMC_sock_accept(struct socket * sock, struct socket ** newsock, int flags)
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof(struct sockaddr);

    int fd = UMC_kernelize(accept4(sock->sk->fd, &addr, &addrlen, flags));
    if (fd < 0) {
	*newsock = NULL;
	return fd;  /* -errno */
    }

    /* fget() starts the receive handler thread for this socket */
    struct file * file = fget(fd);
    if (!file) {
	close(fd);
	return -ENOMEM;
    }

    sys_notice("Accepted incoming socket connection");	//XXX

    *newsock = SOCKET_I(file->inode);
    return E_OK;
}

errno_t
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
void UMC_sock_cb_read(struct sock * sk, int obsolete)	{ sys_warning(""); }
void UMC_sock_cb_write(struct sock * sk)		{ sys_warning(""); }
void UMC_sock_cb_state(struct sock * sk)		{ sys_warning(""); }

/* Callback on event_task when socket fd ready, dispatches to XMIT and/or RECV sk callback */
void
UMC_sock_xmit_event(void * env, uintptr_t events, errno_t err)
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
UMC_sock_recv_event(void * env, uintptr_t events, errno_t err)
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
	sock->sk->sk_data_ready(sock->sk, 0);
    }
}

/******************************************************************************/

void *
genlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
                  const struct genl_family *family, int flags, u8 cmd)
{
        struct nlmsghdr *nlh;
        struct genlmsghdr *hdr;

        nlh = nlmsg_put(skb, portid, seq, family->id, GENL_HDRLEN +
                        family->hdrsize, flags);
        if (nlh == NULL)
                return NULL;

        hdr = nlmsg_data(nlh);
        hdr->cmd = cmd;
        hdr->version = family->version;
        hdr->reserved = 0;

        return (char *) hdr + GENL_HDRLEN;
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
