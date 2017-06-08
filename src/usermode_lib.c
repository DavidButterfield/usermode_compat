/* usermode_lib.c
 * Partial implementation of compatibility for kernel code running in usermode
 * Copyright 2016 David A. Butterfield
 *
 * Most of the shim code is in usermode_lib.h
 */
#define NAME USERMODE_LIB
#include "usermode_lib.h"	/* kernel-code compatibility shim */

struct module __this_module;

_PER_THREAD struct task_struct * current;   /* current task (thread) structure */
extern _PER_THREAD char sys_pthread_name[16];

struct workqueue_struct * UMC_workq;

/* MTE (multi-threaded engine) will be our sys_service provider */
extern sys_service_handle_t MTE_sys_service_get(void);
extern void MTE_sys_service_put(void);

static struct task_struct UMC_init_current_space;

struct _irqthread * UMC_irqthread;   /* delivers "softirq" callbacks */

uint32_t crc32c_uniq;	//XXX hack makes these unique -- no good for matching

_PER_THREAD size_t UMC_size_t_JUNK = 0;	/* for avoiding unused-value gcc warnings */

/* Initialize the usermode_lib usermode compatibility module */
/* mountname is the path to the procfs or sysfs mount point */
errno_t
UMC_init(char * mountname)
{
    /* Set up "current" for this initial thread --
     * Even though this isn't necessarily a (simulated) "kernel" thread (e.g. iscsi-scstd
     * issuing an ioctl), we still set up "current" for it because once the thread passes
     * through the ioctl interface it uses the "kernel" services which expect "current".
     */
    assert_eq(current, NULL);
    UMC_current_init(&UMC_init_current_space, sys_thread_current(),
		     (void *)UMC_init, NULL, sys_pthread_name);
    UMC_current_set(&UMC_init_current_space);

    UMC_irqthread = irqthread_run("UMC_irqthread");

    errno_t err = UMC_fuse_start(mountname);
    expect_noerr(err, "UMC_fuse_start");

    UMC_workq = create_workqueue("UMC_workq");

    return E_OK;
}

void
UMC_exit(void)
{
    assert(current);
    errno_t err;

    err = UMC_fuse_stop();
    if (err == -EINVAL) { /* XXX Ignore for the SIGINT hack */}
    else expect_noerr(err, "UMC_fuse_stop");

    err = UMC_fuse_exit();
    expect_noerr(err, "UMC_fuse_exit");

    expect(UMC_irqthread->SYS != sys_thread_current());
    if (UMC_irqthread->SYS == sys_thread_current()) {
	sys_warning("UMC_exit called on UMC_irqthread");
	exit(-1);
    }

    irqthread_stop(UMC_irqthread);
    irqthread_destroy(UMC_irqthread);
    UMC_irqthread = NULL;

    flush_workqueue(UMC_workq);
    destroy_workqueue(UMC_workq);
    UMC_workq = NULL;

    /* Our caller does the pthread_exit */
}

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

    errno_t ret = sys_event_task_run(irqthread->event_task);  /*** run the event_task logic ***/

    complete(&irqthread->stopped);
	/*** Note this exiting thread's "sys_thread" and "current" may no longer exist ***/
    return ret;
}

/* work queue thread starts running on-thread */
static errno_t
_UMC_work_queue_thr(void * v_workq, sstring_t work_queue_name)
{
    struct workqueue_struct * workq = v_workq;

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

/* The sock->ops point to these shim functions */
ssize_t
sock_no_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
    return UMC_kernelize64(send((sock)->fd, page_address(page) + (offset), (size), (flags)));
}

void
UMC_sock_setsockopt(struct socket * sock, int level, int optname, void *optval, int optlen)
{
    setsockopt(sock->fd, level, optname, optval, optlen);
}

void
UMC_sock_shutdown(struct socket * sock, int k_how)
{
    int u_how;
    if ((k_how & RCV_SHUTDOWN) && (k_how & SEND_SHUTDOWN)) u_how = SHUT_RDWR;
    else if (k_how & RCV_SHUTDOWN) u_how = SHUT_RD;
    else if (k_how & SEND_SHUTDOWN) u_how = SHUT_WR;
    else {
	sys_warning("UMC_sock_shutdown called with bad flags 0x%x", k_how);
	return;
    }
    shutdown(sock->fd, u_how);
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
 * Because our model here is EDGE TRIGGERED, we can get away with doing nothing
 */
void UMC_sock_cb_read(struct sock * sk, int obsolete)	{ DO_NOTHING(); }
void UMC_sock_cb_write(struct sock * sk)		{ DO_NOTHING(); }
void UMC_sock_cb_state(struct sock * sk)		{ DO_NOTHING(); }

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
