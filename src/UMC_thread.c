/* UMC_thread.c
 * Compatibility for kernel code running in usermode
 * Copyright 2016-2019 David A. Butterfield
 */
#define _GNU_SOURCE
#include "UMC_thread.h"
#include "UMC_lock.h"

#define trace_sig(fmtargs...)		printk(fmtargs)

__thread struct task_struct * current;   /* current task (thread) structure */
struct task_struct UMC_init_current_space;

unsigned int nr_cpu_ids;		/* number of CPUs at runtime */

struct task_struct * UMC_irqthread;	/* delivers "softirq" callbacks */

void
_force_sig(unsigned long signo, struct task_struct * task, sstring_t caller_id)
{
    task->signals_pending |= 1<<signo;
    trace_sig("%s: SIGNAL %lu (0x%lx) from task %s (%d) to task %s (%d)",
		caller_id, signo, 1L<<signo, current->comm, current->pid,
		task->comm, task->pid);
    error_t err = pthread_kill(task->pthread, UMC_SIGNAL);
    if (err)
	pr_warning("%s: FAILED TO SIGNAL %lu (0x%lx) from task %s (%d) to task %s (%d) err=%d\n",
		    caller_id, signo, 1L<<signo, current->comm, current->pid,
		    task->comm, task->pid, err);
}

void
_flush_signals(struct task_struct * task, sstring_t caller_id)
{
    if (current == task)
	trace_sig("%s: task %s (%d) FLUSH SIGNALS (0x%lx)", caller_id,
	    current->comm, current->pid, task->signals_pending);
    else
	trace_sig("%s: task %s (%d) FLUSH SIGNALS (0x%lx) of task %s (%d)", caller_id,
	    current->comm, current->pid, task->signals_pending, task->comm, task->pid);

    task->signals_pending = 0;
}

/* A real signal */
static void
UMC_sig_handler(int signo)
{
    trace_sig("REAL SIGNAL %u (0x%lx) received by task %s (%d), pending: 0x%lx",
	    signo, 1L<<signo, current->comm, current->pid, current->signals_pending);
    if (current->signals_pending & (1<<SIGSTKFLT)) {
	current->signals_pending &= ~ (1<<SIGSTKFLT);
	sys_backtrace("SIGSTKFLT");
    }
}

/* Setup for emulated inter-thread signals with a real signal */
void
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
    trace_sig("signals pending tid=%u: 0x%lx", task->pid, task->signals_pending);
    return true;
}

/******************************************************************************/

/* Returns 0 if mutex acquired; otherwise -EINTR on signal */
error_t
_mutex_lock_interruptible(struct mutex * lock, sstring_t whence)
{
    error_t err = _mutex_tryspin(lock, whence);
    if (!err)
	return 0;	    /* got it */

    /* We exhausted the time we're willing to spinwait -- give up the CPU */
    /* But check for signals once in a while */
    while (true) {
	if (signal_pending(current))
	    return -EINTR;		/* wait ends due to signal */

	sys_time_t now = sys_time_now();
	sys_time_t next_check = now + SIGNAL_CHECK_INTERVAL;
	struct timespec const ts_end = {
		.tv_sec = sys_time_delta_to_sec(next_check),
		.tv_nsec = sys_time_delta_mod_sec(next_check)
	};

	err = pthread_mutex_timedlock(&lock->lock, &ts_end);
	if (err == 0)
	    break;			/* got it */
	if (err == ETIMEDOUT)
	    continue;			/* check again for signals */

	pr_warning("pthread_mutex_timedlock(%s) by %s (%d) at %s returns error=%d\n",
		lock->name, current->comm, current->pid, whence, err);
	return -err;
    }

    UMC_LOCK_CLAIM(lock, whence);
    return 0;
}

/* Await a wakeup for a limited time.
 * Called to check if done waiting and/or wait when COND has evaluated false.
 * Return true if full wait is complete, false if full wait is not complete.
 *
 * If INNERLOCKP != NULL, lock acquisition order is LOCKP, INNERLOCKP;
 * The pthread_cond_timedwait() call drops the outer (or solitary) LOCKP.
 */
bool
_UMC_wait_locked(wait_queue_head_t * wq,
		 spinlock_t * lockp, spinlock_t * innerlockp, sys_time_t t_end)
{
    sys_time_t now = sys_time_now();
    sys_time_t next_check;

    spin_lock_assert_holding(lockp);
    if (innerlockp)
	spin_lock_assert_holding(innerlockp);
    // expect_a(t_end + sys_time_delta_of_ms(100), now);	//XXX
    expect_ne(current->state, TASK_RUNNING);
    if (unlikely(!wq->initialized))
	_init_waitqueue_head(wq);

    if (time_after_eq(now, t_end))
	return true;	/* wait ends due to timeout */

    if (current->state != TASK_UNINTERRUPTIBLE && signal_pending(current))
	return true;	/* wait ends due to signal */

    if (time_after(now + SIGNAL_CHECK_INTERVAL, t_end))
	next_check = t_end;
    else
	next_check = now + SIGNAL_CHECK_INTERVAL;

    struct timespec const ts_end = {
		.tv_sec = sys_time_delta_to_sec(next_check),
		.tv_nsec = sys_time_delta_mod_sec(next_check)
    };

    if (innerlockp)
	spin_unlock(innerlockp);
    UMC_LOCK_DISCLAIM(lockp, FL_STR);	/* cond_wait drops LOCK */

    pthread_cond_timedwait(&wq->pcond, &(lockp)->lock, &ts_end);

    UMC_LOCK_CLAIM(lockp, FL_STR);	/* cond_wait reacquires LOCK */
    if (innerlockp)
	spin_lock(innerlockp);

    return false;	/* wait still in progress */
}

/* Return sys_time remaining */
sys_time_t
schedule_timeout_abs(sys_time_t t_end)
{
    if (!current->waitq) {
	pr_warning("Called schedule_timeout_abs() without prepare_to_wait()\n");
	return t_end - sys_time_now();
    }

    spin_lock(&current->waitq->lock);
    if (current->state != TASK_RUNNING)
	_UMC_wait_locked(current->waitq, &current->waitq->lock, NULL, t_end);
    spin_unlock(&current->waitq->lock);

    sys_time_t now = sys_time_now();
    return time_after_eq(now, t_end) ? 0 : (t_end - now);
}

/******************************************************************************/

/* The running kthread exits.
 *
 * It looks like each kthread is designed EITHER to exit ON REQUEST using kthread_stop and
 * kthread_should_stop, OR the thread calls do_exit() when it is DONE, without using the
 * kthread_stop mechanism -- but never a combination of both possibilities.  (XXX but unclear)
 *
 * If that's correct, then do_exit needs to free the task_struct... and it isn't clear what the
 * purpose of the rc is supposed to be if no one is going to wait for it...
 */
void __noreturn
do_exit(long rc)
{
    UMC_current_free(current);
    current = NULL;
    sys_thread_exit((int)rc);	//XXX sys_thread_exit() should take a long
}

/* kthread running on-thread */
static error_t
UMC_kthread_fn(void * v_task)
{
    struct task_struct * task = v_task;
    UMC_current_set(task);

    trace_thread("Thread %s (%u) starts kthread\n", task->comm, task->pid);

    /* Let our creating thread return from kthread_create() */
    complete(&task->started);

    /* completed by wake_up_process() */
    wait_for_completion(&task->start_release);

    //XXXX set cpu affinity
    //XXXX set nice

				      /*** Run the kthread logic ***/
    error_t ret = task->exit_code = task->run_fn(task->run_env);

    trace_thread("Thread %s (%u) EXITS kthread\n", task->comm, task->pid);

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

void
_kthread_start(struct task_struct * task, sstring_t whence)
{
    pr_debug("%s: thread %s (%p, %u) WAKES UP thread %s (%p, %u)\n",
		whence, current->comm, current, current->pid,
		task->comm, task, task->pid);
    /* Let a newly-created thread get going */
    complete(&task->start_release);
}

/* Marks kthread for exit, waits for it to exit, and returns its exit code */
error_t
kthread_stop(struct task_struct * task)
{
    verify(task != current, "task %s (%u) cannot kthread_stop itself",
			    task->comm, task->pid);
    trace_thread("kthread_stop by %s (%u) of %s (%u)",
		current->comm, current->pid, task->comm, task->pid);

    task->should_stop = true;

    /* Wait for the thread to exit */
    if (!wait_for_completion_timeout(&task->stopped, 2 * HZ)) {
	/* Too slow -- jab it */
	pr_warning("kthread_stop of %s (%u) excessive wait -- attempting signal\n",
		    task->comm, task->pid);
	force_sig(SIGSTKFLT, task);	/* try to get a stacktrace */
	if (!wait_for_completion_timeout(&task->stopped, 3 * HZ)) {
	    pr_warning("kthread_stop of %s (%u) excessive wait -- giving up\n",
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

struct task_struct *
_kthread_create(error_t (*fn)(void * env), void * env, char * name, sstring_t caller_id)
{
    struct task_struct * task = UMC_current_alloc();
    init_completion(&task->started);
    init_completion(&task->start_release);
    init_completion(&task->stopped);

    sys_thread_t thread = sys_thread_alloc(UMC_kthread_fn, task, vstrdup(name));
    //mem_buf_allocator_set(thread, caller_id);

    /* name string is copied into comm[] in the task_struct */
    UMC_current_init(task, thread, fn, env, name);
    kfree(name);

    task->SYS->cpu_mask = current->SYS->cpu_mask;
    task->SYS->nice = nice(0);
    task->cpus_allowed = current->cpus_allowed;

    pr_debug("current task %s (%p, %u) creates kthread/task %s (%p)\n",
	     current->comm, current, current->pid, task->comm, task);

    error_t const err = sys_thread_start(task->SYS);
    if (err) {
	/* Failed to start */
	sys_thread_free(task->SYS);
	UMC_current_free(task);
	return ERR_PTR(err);
    }

    /* Wait for new thread to be ready */
    wait_for_completion(&task->started);

    return task;
}

struct task_struct *
UMC_kthread_run(error_t (*fn)(void * env), void * env, char * name, sstring_t caller_id)
{
    struct task_struct * task = _kthread_create(fn, env, name, caller_id);
    assert_ne(task, NULL);
    wake_up_process(task);
    return task;	    /* started OK */
}

/* Run a separate shutdown thread */
struct task_struct *
UMC_run_shutdown(error_t (*fn)(void * env), void * env)
{
    return kthread_run(fn, env, "shutdown_thread");
}

/******************************************************************************/

struct workqueue_struct * UMC_workq;	/* general-purpose work queue */

/* work queue thread running on-thread */
static error_t
_UMC_work_queue_thr(struct workqueue_struct * workq, const char * wq_name)
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
    return 0;
}

error_t
UMC_work_queue_thr(void * v_workq)
{
    struct workqueue_struct * workq = v_workq;
    /* Put name of the queue somewhere visible in a gdb backtrace */
    return _UMC_work_queue_thr(workq, workq->name);
}

void
destroy_workqueue(struct workqueue_struct * workq)
{
    kthread_stop(workq->owner);
    record_free(workq);
}

struct workqueue_struct *
create_workqueue(sstring_t name)
{
    struct workqueue_struct * workq = record_alloc(workq);
    INIT_LIST_HEAD(&workq->list);
    spin_lock_init(&workq->lock);
    init_waitqueue_head(&workq->wake);
    init_waitqueue_head(&workq->flushed);
    strncpy(workq->name, name, sizeof(workq->name)-3);

    spin_lock(&workq->lock);	/* synchronize with owner assertion in UMC_work_queue_thr */

    workq->owner = kthread_run(UMC_work_queue_thr, workq, "%s", name);
    // mem_buf_allocator_set(workq->owner, name);

    spin_unlock(&workq->lock);

    return workq;
}

/* Process "delayed work" timeout events -- runs on UMC_event_task */
void
UMC_delayed_work_process(uintptr_t u_dwork)
{
    struct delayed_work * dwork = (void *)u_dwork;
    dwork->work.fn(&dwork->work);
}

/******************************************************************************/
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
    return 0;
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

/* Deliver system timer alarms to emulated kernel timer */
void
UMC_alarm_handler(void * const v_timer, uint64_t const now, error_t const err)
{
    assert_eq(err, 0);
    if (unlikely(err))
	return;

    struct timer_list * const timer = v_timer;
    //XXXXX expect_ne(timer->alarm, 0);   // Bug when alarm goes off quickly

    //XXX A very recent call to mod_timer() may have updated the expire time
    // assert(time_after_eq(now, jiffies_to_sys_time(timer->expires)));
    assert_ne(timer->function, 0);
    timer->alarm = NULL;

    timer->function(timer->data);
		    /*** Note that timer may already no longer exist ***/
}

/******************************************************************************/

#include <sys/resource.h>	// setpriority()    //XXX extract

error_t
set_user_nice(struct task_struct * task, int niceness)
{
    return UMC_kernelize(setpriority(PRIO_PROCESS, (id_t)task->pid, niceness));
}

error_t
UMC_sched_setscheduler(struct task_struct * task, int policy, struct sched_param * param)
{
//XXX He probably wants the realtime scheduler, but not happening today
//  return UMC_kernelize(sched_setscheduler(task->pid, policy, param));
    // nice him up instead
    set_user_nice(task, param->sched_priority > 0 ? -20 : 0);
    return 0;
}

/******************************************************************************/

/* RCU lock (faked using rwlock) only makes sense with threading */

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
	kfree((char *)this - offset);
    } else {
	/* Call the function specified in call_rcu() */
	this->func(this);
    }
}

/* RCU callback delivery thread running on-thread */
error_t
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

    return 0;
}
