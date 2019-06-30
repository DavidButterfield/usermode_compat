/* usermode_lib.c
 * Partial implementation of compatibility for kernel code running in usermode
 * Copyright 2016 David A. Butterfield
 *
 * Most of the shim code is in usermode_lib.h
 */
#define _GNU_SOURCE 1
#define NAME USERMODE_LIB

#include <sys/socket.h>
#include </usr/include/asm-generic/socket.h> //XXX sys/socket.h included the wrong asm/socket.h

#define  NO_UMC_SOCKETS		// inhibit usermode_lib ucred for one in sys/socket.h
#include "usermode_lib.h"	// must be after sys/socket.h, when NO_UMC_SOCKETS

extern _PER_THREAD char sys_pthread_name[16];

_PER_THREAD struct task_struct * current;   /* current task (thread) structure */
static struct task_struct UMC_init_current_space;

LIST_HEAD(UMC_disk_list);		/* list of struct gendisk */
DEFINE_SPINLOCK(UMC_disk_list_lock);

LIST_HEAD(UMC_pagelist);		/* list for struct page */
DEFINE_SPINLOCK(UMC_pagelist_lock);

static __aligned(PAGE_SIZE) uint8_t empty_zero_page[PAGE_SIZE];
struct page zero_page;

unsigned int nr_cpu_ids;		/* number of CPUs at runtime */

struct timezone sys_tz;

uint32_t crc32c_uniq;	//XXX hack makes these unique -- fake is no good for matching

_PER_THREAD size_t UMC_size_t_JUNK = 0;	/* for avoiding unused-value gcc warnings */

/******************************************************************************/

unsigned long
simple_strtoul(const char * str, char ** endptr, unsigned int base)
{
    return strtoul(str, endptr, base);
}

//XXX should be more strict

error_t
strict_strtoul(const char * str, unsigned int base, unsigned long * var)
{
    errno = 0;
    unsigned long val = strtoul(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return E_OK;
}

error_t
strict_strtoull(const char * str, unsigned int base, unsigned long long * var)
{
    errno = 0;
    unsigned long long val = strtoull(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return E_OK;
}

error_t
strict_strtol(const char * str, unsigned int base, long * var)
{
    errno = 0;
    long val = strtol(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return E_OK;
}

error_t
strict_strtoll(const char * str, unsigned int base, long long * var)
{
    errno = 0;
    long long val = strtoll(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return E_OK;
}

/******************************************************************************/

DEFINE_RWLOCK(UMC_rcu_lock);		/* rwlock substitute for RCU locking */
DEFINE_SPINLOCK(UMC_rcu_cb_list_lock);	/* callback list lock */
struct rcu_head	* UMC_rcu_cb_list;	/* callback list */
DECLARE_WAIT_QUEUE_HEAD(UMC_rcu_cb_wake);   /* RCU callback thread sleep/wake */
struct task_struct * UMC_rcu_cb_thr;

/* Backend for call_rcu(), done on RCU worker thread */
static inline void
UMC_rcu_cb(struct rcu_head * this)
{
    unsigned long offset = (unsigned long)this->func;
    if (offset < 4096) {
	/* Hack for the simple case of freeing a structure */
	kfree((void *)this - offset);
    } else {
	/* Call the function specified in call_rcu() */
	this->func(this);
    }
}

/* RCU callback delivery thread running on-thread */
static error_t
UMC_rcu_cb_fn(void * unused)
{
    while (!kthread_should_stop()) {
	spin_lock(&UMC_rcu_cb_list_lock);

	/* Wait for some RCU callbacks to appear on our work queue */
	if (!UMC_rcu_cb_list)
	    wait_event_locked(UMC_rcu_cb_wake,
			      UMC_rcu_cb_list != NULL || kthread_should_stop(),
			      lock, UMC_rcu_cb_list_lock);

	/* Grab all the RCU callbacks from the queue */
	struct rcu_head * worklist = UMC_rcu_cb_list;
	UMC_rcu_cb_list = NULL;

	spin_unlock(&UMC_rcu_cb_list_lock);

	/* Wait for all the readers to go away */
	synchronize_rcu();

	/* Execute the callbacks that we grabbed before the synchronize */
	while (worklist) {
	    struct rcu_head * this = worklist;
	    worklist = worklist->next;
	    UMC_rcu_cb(this);
	}
    }

    return E_OK;
}

/******************************************************************************/

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

#define trace_thread(fmtargs...)    //  sys_notice(fmtargs)

struct task_struct *
UMC_kthread_run(error_t (*fn)(void * env), void * env, string_t name, sstring_t caller_id)
{
    struct task_struct * task = _kthread_create(fn, env, name, caller_id);
    assert(task);
    wake_up_process(task);
    return task;	    /* started OK */
}

struct task_struct *
UMC_run_shutdown(error_t (*fn)(void * env), void * env)
{
    return kthread_run(fn, env, "shutdown_thread");
}

/* Marks kthread for exit, waits for it to exit, and returns its exit code */
error_t
kthread_stop(struct task_struct * task)
{
    verify(task != current, "task %s (%u) cannot kthread_stop itself",
			    task->comm, task->pid);
    sys_notice("kthread_stop by %s (%u) of %s (%u)",
		current->comm, current->pid, task->comm, task->pid);

    task->should_stop = true;

    /* Wait for the thread to exit */
    if (!wait_for_completion_timeout(&task->stopped, 2 * HZ)) {
	/* Too slow -- jab it */
	sys_warning("kthread_stop of %s (%u) excessive wait -- attempting signal",
		    task->comm, task->pid);
	force_sig(SIGSTKFLT, task);	/* try to get a stacktrace */
	if (!wait_for_completion_timeout(&task->stopped, 3 * HZ)) {
	    sys_warning("kthread_stop of %s (%u) excessive wait -- giving up",
			task->comm, task->pid);
	    return -EBUSY;
	}
    }

    /* Take the lock to sync with the end of UMC_kthread_fn() */
    spin_lock(&task->stopped.wait.lock);    /* no matching unlock */

    error_t const ret = task->exit_code;

    sys_thread_free(task->SYS);
    UMC_current_free(task);

    return ret;
}

/* The running kthread exits.
 *
 * It looks like each kthread is designed EITHER to exit ON REQUEST using kthread_stop and
 * kthread_should_stop, OR the thread calls do_exit() when it is DONE, without using the
 * kthread_stop mechanism -- but never a combination of both possibilities.  (XXX but unclear)
 *
 * If that's correct, then do_exit needs to free the task_struct... and it isn't clear what the
 * purpose of the rc is supposed to be if no one is going to wait for it... XXX Investigate
 */
void __noreturn
do_exit(long rc)
{
    UMC_current_free(current);
    current = (void *)MEM_ZAP_64;
    sys_thread_exit(rc);
}

/* kthread running on-thread */
error_t
UMC_kthread_fn(void * v_task)
{
    struct task_struct * task = v_task;
    UMC_current_set(task);

    trace_thread("Thread %s (%u) starts kthread task %s (%p)\n",
		sys_thread_name(sys_thread), gettid(), task->comm, task);

    /* Let our creating thread return from kthread_create() */
    complete(&task->started);

    /* completed by wake_up_process() */
    wait_for_completion(&task->start_release);

				      /*** Run the kthread logic ***/
    error_t ret = task->exit_code = task->run_fn(task->run_env);

    sys_notice("Thread %s (%u) EXITS kthread (task %s (%p))\n",
		sys_thread_name(sys_thread), gettid(), task->comm, task);

    /* If this thread is not being stopped by another thread,
     * then do self-cleanup through do_exit()
     */
    if (!kthread_should_stop())
	do_exit(0);

    /* Let our stopping thread return from kthread_stop().
     * The stopping thread will free our current and sys_thread.
     */
    spin_lock(&task->stopped.wait.lock);
    complete(&task->stopped);
    spin_unlock(&task->stopped.wait.lock);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/

    return ret;
}

struct _irqthread * UMC_irqthread;	/* delivers "softirq" callbacks */

/* irqthread runs event_task on-thread */
error_t
UMC_irqthread_fn(void * v_irqthread)
{
    struct _irqthread * irqthread = v_irqthread;
    struct task_struct * task = irqthread->current;
    UMC_current_set(task);

    trace_thread("Thread %s (%u) starts irqthread task %s (%p)\n",
		sys_thread_name(sys_thread), gettid(), task->comm, task);

    complete(&irqthread->started);
    //XXX affinity?
    //XXX wait for start release?

    error_t ret = sys_event_task_run(irqthread->event_task);  /*** run the event_task logic ***/

    sys_notice("Thread %s (%u) EXITS irqthread task %s (%p)\n",
		sys_thread_name(sys_thread), gettid(), task->comm, task);

    complete(&irqthread->stopped);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/
    return ret;
}

struct workqueue_struct * UMC_workq;	/* general-purpose work queue */

/* work queue thread running on-thread */
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

/* tasklet thread running on-thread */
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
	.release	= blk_queue_release,
};

static void
device_release(struct kobject *kobj)
{
    struct device * dev = container_of(kobj, struct device, kobj);
    record_free(dev->disk);
    record_free(dev);
}

static struct attribute *default_device_attrs[] = { };

struct kobj_type device_ktype = {
//      .sysfs_ops      = &device_sysfs_ops,
	.default_attrs  = default_device_attrs,
	.release	= device_release,
};

/******************************************************************************/
/* net/core/skbuff.c */

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
	skb->truesize = size + sizeof(struct sk_buff);
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

/******************************************************************************/

struct net init_net;

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
#ifdef TRACE_socket
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
		NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port));

    error_t err = UMC_kernelize(connect(sock->sk->fd, addr, addrlen));
    if (!err) {
	sock->sk->sk_state = TCP_ESTABLISHED;
	UMC_sock_filladdrs(sock);
    }

    sys_notice("%s (%d) connected socket fd=%d to %d.%d.%d.%d port %u err=%d",
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
	    UMC_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));	//XXX
	}

	err = UMC_kernelize(bind(sock->sk->fd, addr, addrlen));
	if (err == E_OK) {
	    sys_notice("%s (%d) binds socket fd=%d to %d.%d.%d.%d port %u",
			current->comm, current->pid, sock->sk->fd,
			NIPQUAD(inaddr->sin_addr), htons(inaddr->sin_port));
	    UMC_sock_filladdrs(sock);
	} else {
	    sys_warning("%s (%d) ERROR %d binding fd=%d to %d.%d.%d.%d port %u",
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
    return UMC_kernelize64(send(sock->sk->fd, page_address(page) + offset, size, flags));
}

error_t
UMC_sock_recvmsg(struct socket * sock, struct msghdr * msg,
	      size_t nbytes, int flags, sstring_t caller_id)
{
    ssize_t rc = 123456789;
#if 1	// DEBUG
    struct iovec * iov = msg->msg_iov;
    int niov = msg->msg_iovlen;
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
	if (err != E_OK) {
	    sys_warning("%s: fd=%d failed to set receive timeout to jiffies=%lu sec=%lu usec=%lu",
		caller_id, sock->sk->fd, sock->sk->UMC_rcvtimeo, optval.tv_sec, optval.tv_usec);
	} else {
#ifdef TRACE_socket
	    sys_notice("%s: fd=%d changed receive timeout to jiffies=%lu sec=%lu usec=%lu",
		caller_id, sock->sk->fd, sock->sk->UMC_rcvtimeo, optval.tv_sec, optval.tv_usec);
#endif
	}
    }
#endif

    sys_time_t t_end = sys_time_now() + jiffies_to_sys_time(sock->sk->UMC_rcvtimeo);
restart:
    rc = UMC_kernelize(recvmsg(sock->sk->fd, msg, flags));

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
#ifdef TRACE_socket
	if ((size_t)rc < nbytes) {
	    sys_warning("%s: received short read %ld/%lu on fd=%d flags=0x%x",
			caller_id, rc, nbytes, sock->sk->fd, flags);
	} else {
	    // sys_notice("%s: received full read %ld/%lu on fd=%d flags=0x%x",
	    //	    caller_id, rc, nbytes, sock->sk->fd, flags);
	}
#endif
	/* Advance the msg by the number of bytes we received into it */
	size_t skipbytes = (size_t)rc;
	while (skipbytes && skipbytes >= msg->msg_iov->iov_len) {
	    // msg->msg_iov->iov_base += msg->msg_iov->iov_len; //XXX needed?
	    skipbytes -= msg->msg_iov->iov_len;
	    msg->msg_iov->iov_len = 0;
	    ++msg->msg_iov;
	    assert(msg->msg_iovlen);
	    --msg->msg_iovlen;
	}
	if (skipbytes) {
	    /* It's not OK to add when skipbytes == zero */
	    msg->msg_iov->iov_base += skipbytes;
	    msg->msg_iov->iov_len -= skipbytes;
	}
    } else if (rc == 0) {
	sys_notice("%s: EOF on fd=%d flags=0x%x", caller_id, sock->sk->fd, flags);
    } else {
	if (rc == -EINTR) {
	    sys_notice("%s: recvmsg returns -EINTR on fd=%d flags=0x%x",
			    caller_id, sock->sk->fd, flags);
	} else if (rc == -EAGAIN) {
	    if (!(flags & MSG_DONTWAIT)) {  //XXXX probably SO_NONBLOCK too
		if (sock->sk->UMC_rcvtimeo == 0 || sock->sk->UMC_rcvtimeo >= JIFFY_MAX) {
#ifdef TRACE_socket
		    sys_notice("%s: recvmsg ignores -EAGAIN on fd=%d flags=0x%x", caller_id, sock->sk->fd, flags);
#endif
		    usleep(100);	    //XXXXX
		    goto restart;   //XXX doesn't adjust time remaining
		}
		#define T_SLOP jiffies_to_sys_time(1)
		if (sys_time_now() < t_end - T_SLOP) {
		    sys_notice("%s: recvmsg ignores early -EAGAIN on fd=%d now=%lu end=%lu flags=0x%x",
				caller_id, sock->sk->fd, sys_time_now(), t_end, flags);
		    usleep(100);	    //XXXXX
		    goto restart;   //XXX doesn't adjust time remaining
		}
#ifdef TRACE_socket
		sys_notice("%s: recvmsg returns -EAGAIN on fd=%d timeout=%lu jiffies flags=0x%x",
			    caller_id, sock->sk->fd, sock->sk->sk_rcvtimeo, flags);
#endif
	    } else {
		// sys_notice("%s: recvmsg(MSG_DONTWAIT) returns -EAGAIN on fd=%d timeout=%lu jiffies flags=0x%x",
			    // caller_id, sock->sk->fd, sock->sk->sk_rcvtimeo, flags);
	    }
	} else {
	    sys_warning("%s: ERROR %"PRId64" '%s'on fd=%d flags=0x%x", caller_id,
			    rc, strerror((int)-rc), sock->sk->fd, flags);
	}
    }
    return (int)rc;
}

//XXX Probably doesn't need the "skip" from UMC_sock_recvmsg()
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
    if (unlikely(err != E_OK)) {
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
    if (unlikely(err != E_OK)) {
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

static void
on_netlink_error(struct sock * sk)
{
    sys_notice("state change on netlink fd=%d", sk->fd);
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
	    dst_addr.sin_addr.s_addr = htonl(224<<24 | 0<<16 | 0<<8 | group);	//XXXXXX
	    dst_addr.sin_port = 7789;						//XXXXXX
	} else
	    sys_warning("multicast group=%d out of range [1-31]", group);
    }

    ssize_t nsent = sendto(sk->fd, skb->data, skb->len, flags, &dst_addr, sizeof(dst_addr));

    error_t ret = UMC_kernelize(nsent);
    if (ret < 0) {
	sys_warning("error %d sending on netlink fd=%d", ret, sk->fd);
	return ret;
    }

    skb->data += nsent;
    skb->len -= nsent;

    kfree_skb(skb);	/* drop one reference to the skb */

    return E_OK;
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

#if 0	//XXX
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
    assert_eq(sk->netlink_rcv, genl_rcv);
    expect_eq(len, 0);

    struct sk_buff * skb = alloc_skb(NETLINK_BUFSIZE, IGNORED);

    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t rc = UMC_kernelize(recvfrom(sk->fd, skb_tail_pointer(skb),
			NETLINK_BUFSIZE, MSG_DONTWAIT, &src_addr, &addrlen));

    if (rc <= 0) {
	kfree_skb(skb);
	if (rc == 0) {
	    sys_notice("Zero-length datagram on netlink fd=%d", sk->fd);
	    return;
	} else if (errno == EAGAIN) {
	    sys_notice("EAGAIN on netlink fd=%d", sk->fd);
	    return;
	}
	sys_warning("error %ld on netlink fd=%d", rc, sk->fd);

	struct socket * sock = container_of(sk, struct socket, sk_s);   /* annoying */
	init_net.genl_sock = NULL;  //XXXXX
	sock_release(sock);

	//XXXX Should re-establish netlink service socket

	return;
    }

    skb->len += rc;
    skb->tail += rc;
    verify_le(skb->tail, skb->end);

    skb->sk = sk;
    NETLINK_CB(skb).pid = ntohs(src_addr.sin_port);

    sk->netlink_rcv(skb);

    kfree_skb(skb);
}

extern void UMC_genl_init(void);

/* Open a datagram socket for the kernel side of the simulated netlink */
static void
netlink_establish(void)
{
    if (init_net.genl_sock) {
	sys_warning("netlink server already established!");
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
	perror("UMC_init netlink: ");
	sys_warning("UMC_init could not open generic netlink");

    } else if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("UMC_init netlink bind: ");
	sys_warning("UMC_init could not bind generic netlink");
	close(fd);

    } else {
	sys_notice("starting netlink server fd=%d", fd);

	struct file * file = _fget(fd);
	if (!file) {
	    sys_warning("could not allocate file for netlink socket");
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

static void
netlink_shutdown(void)
{
    struct sock * sk = init_net.genl_sock;
    if (!sk) {
	sys_warning("netlink server not established!");
	return;
    }
    sys_notice("CLOSE netlink fd=%d", sk->fd);

    sock_release(sock_of_sk(sk));
    init_net.genl_sock = NULL;
}

/******************************************************************************/

void
dump_stack(void)
{
    sys_backtrace("kernel-code call to dump_stack()");
}

/* A real signal */
static void
UMC_sig_handler(int signo)
{
    sys_notice("REAL SIGNAL %u (0x%lx) received by task %s (%d), pending: 0x%lx",
	    signo, 1L<<signo, current->comm, current->pid, current->signals_pending);
    if (current->signals_pending & (1<<SIGSTKFLT)) {
	current->signals_pending &= ~ (1<<SIGSTKFLT);
	sys_backtrace("SIGSTKFLT");
    }
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
    sys_tz.tz_minuteswest = timezone/60;    /* see tzset(3) */
    sys_tz.tz_dsttime = daylight;	    /* see tzset(3) */

    idr_init_cache();

    /* Initialize a page of zeros for general use */
    struct page * page = &zero_page;
    kref_init(&page->kref);
    mutex_init(&page->lock);
    page->order = 0;	/* single page */
    page_address(page) = empty_zero_page;
    //XXX is this really supposed to be on UMC_page_list?
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

    UMC_sig_setup();

    /* Threads */

    /* fuse forks, so start it before anything that opens file descriptors */
    error_t err = UMC_fuse_start(mountname);
    expect_noerr(err, "UMC_fuse_start");

    UMC_rcu_cb_thr = kthread_run(UMC_rcu_cb_fn, NULL, "%s", "RCU_callback");

    UMC_irqthread = irqthread_run("UMC_irqthread");

    UMC_workq = create_workqueue("UMC_workq");

    netlink_establish();

    return E_OK;
}

error_t
UMC_exit(void)
{
    error_t err;
    assert(current);

    err = UMC_fuse_stop();
    if (err == -EINVAL) { /* XXX Ignore for the SIGINT hack */ }
    else expect_noerr(err, "UMC_fuse_stop");

    if (!err) {
	err = UMC_fuse_exit();
	expect_noerr(err, "UMC_fuse_exit");
    }

    netlink_shutdown();

    irqthread_stop(UMC_irqthread);
    irqthread_destroy(UMC_irqthread);
    UMC_irqthread = NULL;

    flush_workqueue(UMC_workq);
    destroy_workqueue(UMC_workq);
    UMC_workq = NULL;

    kthread_stop(UMC_rcu_cb_thr);

    idr_exit_cache();

    return err;
}

/******************************************************************************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

int
__ratelimit(struct ratelimit_state *rs)
{
    return 1;	    /* no ratelimit */
}

#endif

extern int sysinfo(struct sysinfo *);

void
si_meminfo(struct sysinfo *si)
{
    struct sysinfo si_space;
    int rc = sysinfo(&si_space);
    expect_rc(rc, sysinfo);
    /* Kernel code appears to assume the unit is PAGE_SIZE */
    unsigned int unit = si_space.mem_unit;
    si->totalram = si_space.totalram * unit / PAGE_SIZE;
    si->totalhigh = si_space.totalhigh * unit / PAGE_SIZE;
}

#include <sys/resource.h>

error_t
UMC_sched_setscheduler(struct task_struct * task, int policy, struct sched_param * param)
{
//XXX He probably wants the realtime scheduler, but not happening today
//  return UMC_kernelize(sched_setscheduler(task->pid, policy, param));
    // nice him up instead
    setpriority(PRIO_PROCESS, (id_t)task->pid, param->sched_priority > 0 ? -20 : 0);
    return E_OK;
}

#include "UMC_genl.c"

/* Import source from the reference kernel */
#include "klib/dec_and_lock.c"
#include "klib/bitmap.c"
#include "klib/idr.c"
// #include "klib/libcrc32c.c"
#include "klib/nlattr.c"
#include "klib/rbtree.c"
