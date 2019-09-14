/* UMC_thread.h -- usermode compatibility for tasks and scheduling
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_THREAD_H
#define UMC_THREAD_H
#include "UMC_sys.h"
#include <pthread.h>
#include <signal.h>

#define trace_thread(args...)	    //	nlprintk(args)

#define	NR_CPUS				BITS_PER_LONG

struct mutex {
    struct task_struct       * volatile owner;		/* exclusive holder, if any */
    struct task_struct       * volatile nestor;		/* last nestor, if any */
    atomic_t				nest;		/* lock nest monster (for spinlock) */
    pthread_mutex_t		        lock;
    sstring_t				name;
    sstring_t				last_locker;	/* FILE:LINE of last locker */
};

typedef struct mutex			spinlock_t;	/* using only _trywait() */

typedef struct { unsigned long bits[(NR_CPUS+BITS_PER_LONG-1) / BITS_PER_LONG]; } cpumask_t;

/* The actual queue itself is managed by pthreads, not visible here */
//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
typedef struct wait_queue_head {
    spinlock_t		    lock;	    /* synchronizes pcond when non-locked wait */
    pthread_cond_t	    pcond;	    /* sleep awaiting condition change */
    bool	   volatile initialized;
    bool		    is_exclusive;   /* validate XXX limitation assumption */
} wait_queue_head_t;

struct completion {
    atomic_t		    done;
    wait_queue_head_t	    wait;
};

#define TASK_COMM_LEN			16
#include <errno.h>

/* A kthread is implemented on top of a sys_thread --
 * each kthread's "current" points to that thread's instance of struct task_struct
 */
struct task_struct {
    error_t		  (*run_fn)(void *);/* kthread's work function */
    void		  * run_env;	    /* argument to run_fn */
    int			    exit_code;
    bool		    affinity_is_set;
    unsigned long  volatile signals_pending;	/* send_sig/signal_pending */
    unsigned int	    state;

    sys_thread_t	    SYS;	    /* pointer to system thread info */
    pthread_t		    pthread;
    int			    niceness;

    struct completion	    started;	    /* synchronize thread start */
    struct completion	    start_release;  /* synchronize thread start */
    struct completion	    stopped;	    /* synchronize thread stop */
    struct wait_queue_head * waitq;	    /* for wake_up_process */

    struct sys_event_task  * event_task;

    /* kernel code compatibility */
    cpumask_t		    cpus_allowed;
    bool	   volatile should_stop;    /* kthread shutdown signalling */
    char		    comm[TASK_COMM_LEN];  /* thread name */
    pid_t		    pid;	    /* tid, actually */
    int			    flags;	    /* ignored */
    void		  * io_context;	    /* unused */
    struct mm_struct      * mm;		    /* unused */
    void		  * plug;	    //XXXX unimplemented
};

extern __thread struct task_struct * current;    /* current thread */

#include "UMC_lock.h"	    /* after task_struct and current defined */

extern wait_queue_head_t    UMC_rcu_cb_wake;/* RCU callback queue */

typedef struct wait_queue_entry	{ /*unused*/ } wait_queue_entry_t;

extern struct task_struct UMC_init_current_space;   /* current for thread tid==pid */

extern struct task_struct * UMC_irqthread;
extern error_t irqthread_stop(struct task_struct *);

#define irqthread_run(cfg, fmtargs...)    _irqthread_run((cfg), kasprintf(0, fmtargs), FL_STR)
extern struct task_struct * _irqthread_run(struct sys_event_task_cfg *, char *, sstring_t);

/******************************************************************************/

#define trace_signal(fmtargs...)	nlprintk(fmtargs)

#define UMC_SIGNAL			SIGHUP	/* inter-thread signal */

extern void UMC_sig_setup(void);
extern int signal_pending(struct task_struct * task);

#define send_sig(signo, task, priv)	_send_sig((signo), (task), (priv), FL_STR)
extern void _send_sig(unsigned long signo, struct task_struct * task,
					    int priv, sstring_t caller_id);

#define flush_signals(task)		_flush_signals((task), FL_STR)
extern void _flush_signals(struct task_struct * task, sstring_t caller_id);

#define allow_signal(signum)		DO_NOTHING()

/******************************************************************************/
/*** Wait Queue -- wait (if necessary) for a condition to be true ***/

#define TASK_RUNNING			0
#define TASK_INTERRUPTIBLE		1
#define TASK_UNINTERRUPTIBLE		2

#define DEFINE_WAIT(name)		struct wait_queue_entry name = { }

/* The pcond has to be initialized at runtime */
#define WAIT_QUEUE_HEAD_INIT(name)	(struct wait_queue_head){ \
					   .lock = SPINLOCK_UNLOCKED(#name), \
					   /* .pcond = PTHREAD_COND_INITIALIZER, */ \
					   .initialized = false, \
					   .is_exclusive = false}

#define DECLARE_WAIT_QUEUE_HEAD(name)	wait_queue_head_t name = WAIT_QUEUE_HEAD_INIT(name)

/* init_waitqueue_head is suitable for initializing dynamic waitqueues */
#define init_waitqueue_head(WAITQ)  /* before exposing them to the view of other threads */ \
	    do { \
		record_zero(WAITQ); \
		spin_lock_init(&(WAITQ)->lock); \
		pthread_condattr_t attr; \
		pthread_condattr_init(&attr); \
		pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
		pthread_cond_init(&(WAITQ)->pcond, &attr); \
		pthread_condattr_destroy(&attr); \
		(WAITQ)->initialized = true; \
	    } while (0)

#define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(WAITQ)  wait_queue_head_t WAITQ; \
						init_waitqueue_head(&WAITQ)

/* This is for auto-initialization of static waitqueues partially-initialized at compile-time */
#define _init_waitqueue_head(WAITQ) \
	    do { \
		spin_lock(&(WAITQ)->lock); \
		if (!(WAITQ)->initialized) { \
		    pthread_condattr_t attr; \
		    pthread_condattr_init(&attr); \
		    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC); \
		    pthread_cond_init(&(WAITQ)->pcond, &attr); \
		    pthread_condattr_destroy(&attr); \
		    (WAITQ)->initialized = true; \
		} \
		spin_unlock(&(WAITQ)->lock); \
	    } while (0)

/* The SIGNAL_CHECK_INTERVAL is a hack to allow checking for unwoken events like signals.  Note
 * that pthread_cond_timedwait() never returns EINTR, so signals do not interrupt it.  We wake
 * up to recheck the COND each time interval, even if no wakeup has been sent; so that interval
 * is the maximum delay between an unwoken event and the thread noticing it.
 * XXXX fix so that we can wake them up
 */
#define SIGNAL_CHECK_INTERVAL	sys_time_delta_of_ms(150)   /* signal check interval */

/* Returns 0 if mutex acquired; otherwise -EINTR on signal */
extern error_t _mutex_lock_interruptible(struct mutex * lock, sstring_t whence);

/* Await a wakeup for a limited time.
 * Called to check if done waiting and/or wait when COND has evaluated false.
 * Return true if full wait is complete, false if full wait is not complete.
 *
 * If INNERLOCKP != NULL, lock acquisition order is LOCKP, INNERLOCKP;
 * The pthread_cond_timedwait() call drops the outer (or solitary) LOCKP.
 */
extern bool _UMC_wait_locked(wait_queue_head_t * wq,
		 spinlock_t * lockp, spinlock_t * innerlockp, sys_time_t t_end);

#define MAX_SCHEDULE_TIMEOUT		JIFFY_MAX

/* Return sys_time remaining */
extern sys_time_t schedule_timeout_abs(sys_time_t t_end);

/* Return jiffies remaining */
#define schedule_timeout(jdelta) ({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    jiffies_of_sys_time(schedule_timeout_abs(t_end)); \
})

#define schedule() schedule_timeout_abs(SYS_TIME_MAX)

#define prepare_to_wait(WQ, W, TSTATE) do { \
    current->waitq = (WQ); \
    current->state = (TSTATE); \
    _USE(W); \
} while (0)

#define finish_wait(WQ, W) do { \
    current->waitq = NULL; \
    current->state = TASK_RUNNING; \
} while (0)

/* Returns the number of jiffies remaining */
#define schedule_timeout_interruptible(jdelta) ({ \
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(sti_wait); \
	prepare_to_wait(&sti_wait, 0, TASK_INTERRUPTIBLE); \
	int ret = schedule_timeout(jdelta); \
	finish_wait(&sti_wait, 0); \
	ret; \
})

#define schedule_timeout_uninterruptible(jdelta) ({ \
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(stu_wait); \
	prepare_to_wait(&stu_wait, 0, TASK_UNINTERRUPTIBLE); \
	int ret = schedule_timeout(jdelta); \
	finish_wait(&stu_wait, 0); \
	ret; \
})

/* With all of these wait macros it is important that COND evaluate TRUE at most once! */

/* Returns true when condition is seen to be met, or false after timeout or signal */
#define UMC_wait_locked(WAITQ, COND, LOCKP, INNERLOCKP, t_end) \
({ \
    bool UMC_wl_cond_met; \
    while (!(UMC_wl_cond_met = !!(COND))) { \
	if (_UMC_wait_locked(&(WAITQ), (LOCKP), (INNERLOCKP), t_end)) \
	    break; /* timeout or signal */ \
    } \
    UMC_wl_cond_met ? true : !!(COND); /* return */ \
})

/* Common internal helper for exclusive wakeups */
#define _wait_event_locked2(WAITQ, COND, LOCKP, INNERLOCKP) \
do { \
    (WAITQ).is_exclusive = true; \
    prepare_to_wait(&(WAITQ), 0, TASK_INTERRUPTIBLE); \
    UMC_wait_locked((WAITQ), (COND), (LOCKP), (INNERLOCKP), SYS_TIME_MAX); \
    finish_wait((WAITQ), 0); \
} while (0)

/* Caution: these "wait_event" macros use unnatural pass-by-name semantics */
/* XXX Limitation: locked waits are always exclusive, non-locked always non-exclusive */

/* Wait Event with exclusive wakeup, NO timeout, interruptible, and spinlock */
#define wait_event_locked(WAITQ, COND, lock_type, LOCK) \
		_wait_event_locked2((WAITQ), (COND), &(LOCK), NULL)

/* Wait Event with exclusive wakeup, NO timeout, interruptible, and TWO spinlocks --
 * Lock acquisition order is LOCK, INNERLOCK
 */
#define wait_event_locked2(WAITQ, COND, LOCK, INNERLOCK) \
		_wait_event_locked2((WAITQ), (COND), &(LOCK), &(INNERLOCK))

//XXX Testing COND outside the lock because otherwise the lock is already held by the thread
//    when DRBD recurses back into another wait from inside the COND of the first wait.

/* Common internal helper for non-exclusive wakeups --
 * returns true when condition is seen to be met, or false after timeout or signal.
 */
#define UMC_wait_unlocked(WAITQ, COND, LOCKP, INNERLOCKP, t_end) \
({ \
    bool UMC_wl_cond_met; \
    while (!(UMC_wl_cond_met = !!(COND))) { \
	spin_lock(&(WAITQ).lock); \
	bool _done = _UMC_wait_locked(&(WAITQ), (LOCKP), (INNERLOCKP), t_end); \
	spin_unlock(&(WAITQ).lock); \
	if (_done) \
	    break; /* timeout or signal */ \
    } \
    UMC_wl_cond_met ? true : !!(COND); /* return */ \
})

/* Common internal helper for non-exclusive wakeups --
 * Returns true if condition was seen to be met, false otherwise
 */
#define wait_event_timeout_abs(WAITQ, COND, T_STATE, t_end) \
({ \
    expect_eq((WAITQ).is_exclusive, false, "Mixed waitq exclusivity"); \
    prepare_to_wait(&(WAITQ), 0, (T_STATE)); \
    bool weta_cond_met = UMC_wait_unlocked((WAITQ), (COND), &(WAITQ).lock, NULL, (t_end)); \
    finish_wait((WAITQ), 0); \
    weta_cond_met; \
})

/* Non-exclusive wakeup with NO timeout, uninterruptible */
#define wait_event(WAITQ, COND) \
({ \
    bool we_cond_met = \
	    wait_event_timeout_abs((WAITQ), (COND), TASK_UNINTERRUPTIBLE, SYS_TIME_MAX); \
    expect_eq(we_cond_met, true); \
})

/* Non-exclusive wakeup WITH timeout, uninterruptible --
 * Returns ticks remaining (minimum one) if the condition was seen to be met.
 * Returns zero if it times out.
 */
#define wait_event_timeout(WAITQ, COND, jdelta) \
({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    bool wet_cond_met = wait_event_timeout_abs((WAITQ), (COND), TASK_UNINTERRUPTIBLE, t_end); \
    sys_time_t now = sys_time_now(); \
    !wet_cond_met ? 0 : time_after_eq(now, t_end) ? 1 : \
		    jiffies_of_sys_time(t_end - now) ?: 1; \
})

/* Non-exclusive wakeup with NO timeout, interruptible --
 * Returns zero if the condition was seen to be met, otherwise -ERESTARTSYS
 */
#define wait_event_interruptible(WAITQ, COND) \
({ \
    bool wei_cond_met = \
	    wait_event_timeout_abs((WAITQ), (COND), TASK_INTERRUPTIBLE, SYS_TIME_MAX); \
    expect_eq(wei_cond_met || signal_pending(current), true); \
    wei_cond_met ? 0 : -ERESTARTSYS; \
})

/* Non-exclusive wakeup WITH timeout, interruptible --
 * Returns ticks remaining (minimum one) if the condition was seen to be met.
 * Returns -ERESTARTSYS if signalled, or zero if it times out.
 */
#define wait_event_interruptible_timeout(WAITQ, COND, jdelta) \
({ \
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta); \
    bool weit_cond_met = wait_event_timeout_abs((WAITQ), (COND), TASK_INTERRUPTIBLE, t_end); \
    sys_time_t now = sys_time_now(); \
    !weit_cond_met ? (signal_pending(current) ? -ERESTARTSYS : 0) \
	      : (time_after_eq(now, t_end) ? 1 : jiffies_of_sys_time(t_end - now) ?: 1); \
})

/* First change the condition being waited on, then call wake_up*() --
 * These may be called with or without holding the associated lock;
 * if called without, the caller is responsible for handling the races.
 */
#define wake_up_one(WAITQ) \
	    do { \
		pthread_cond_signal(&(WAITQ)->pcond); \
	    } while (0)

#define wake_up_all(WAITQ) \
	    do { \
		pthread_cond_broadcast(&(WAITQ)->pcond); \
	    } while (0)

//XXX Limitation:  each queue is either always exclusive wakeup, or always non-exclusive wakeup
#define wake_up(WAITQ) \
	    do { \
		if ((WAITQ)->is_exclusive) \
		    wake_up_one(WAITQ); \
		else \
		    wake_up_all(WAITQ); \
	    } while (0)

/*** Completion ***/

#define COMPLETION_INIT(name)	{	.wait = WAIT_QUEUE_HEAD_INIT((name).wait), \
					.done = { 0 } \
				}

#define DECLARE_COMPLETION(name)	struct completion name = COMPLETION_INIT(name)


#define init_completion(c)		do { init_waitqueue_head(&(c)->wait); \
					     atomic_set(&(c)->done, 0); \
					} while (0)

#define COMPLETION_INITIALIZER_ONSTACK(c)  COMPLETION_INIT(c)

#define DECLARE_COMPLETION_ONSTACK(name) struct completion name; \
					 init_completion(&name)

#define complete(c) \
	    do { atomic_inc(&(c)->done); wake_up(&(c)->wait); } while (0)

#define complete_all(c) \
	    do { atomic_set(&(c)->done, 1ul<<30); wake_up_all(&(c)->wait); } while (0)

/* Returns ticks remaining (min 1) if the completion occurred, 0 if it timed out */
static inline int
wait_for_completion_timeout(struct completion * c, uint32_t jdelta)
{
    sys_time_t t_end = sys_time_abs_of_jdelta(jdelta);
    while (atomic_dec_return(&c->done) < 0) {
	/* Overdraft -- give it back */
	atomic_inc(&c->done);
	wait_event_timeout_abs(c->wait, atomic_read(&c->done) > 0, TASK_UNINTERRUPTIBLE, t_end);
	if (!atomic_read(&c->done))
	    return 0;	/* timed out */
    }
    sys_time_t now = sys_time_now(); \
    return time_after_eq(now, t_end) ? 1 : \
		    (int)jiffies_of_sys_time(t_end - now) ?: 1; \
}

static inline void
wait_for_completion(struct completion * c)
{
    while (atomic_dec_return(&c->done) < 0) {
	/* Overdraft -- give it back */
	atomic_inc(&c->done);
	wait_event(c->wait, atomic_read(&c->done) > 0);
    }
}

/******************************************************************************/
/*** Sleepable rw_semaphore ***/

struct rw_semaphore {
    rwlock_t				rwlock;
    wait_queue_head_t			waitq;
};

#define RW_SEM_UNLOCKED(rwname)		{ .rwlock = RW_LOCK_UNLOCKED(rwname), \
					  .waitq =  WAIT_QUEUE_HEAD_INIT(rwname) }

#define DECLARE_RWSEM(rw_sem)		struct rw_semaphore rw_sem = RW_SEM_UNLOCKED(rw_sem)

#define down_read_trylock(rw_sem)	read_lock_try(&(rw_sem)->rwlock)
#define down_write_trylock(rw_sem)	write_lock_try(&(rw_sem)->rwlock)

#define down_read(rw_sem)		wait_event((rw_sem)->waitq, down_read_trylock(rw_sem))
#define down_write(rw_sem)		wait_event((rw_sem)->waitq, down_write_trylock(rw_sem))

#define up_read(rw_sem)			({  read_unlock(&(rw_sem)->rwlock); wake_up_one(&(rw_sem)->waitq); })
#define up_write(rw_sem)		({ write_unlock(&(rw_sem)->rwlock); wake_up_all(&(rw_sem)->waitq); })

/******************************************************************************/
/*** Kthread (simulated kernel threads) ***/

#define TC_PRIO_INTERACTIVE_BULK	4
#define TC_PRIO_INTERACTIVE		6

#define UMC_current_alloc()	((struct task_struct *)vzalloc(sizeof(struct task_struct)))

#define UMC_current_init(task, _SYS, _FN, _ENV, _COMM) \
	    ({ \
		struct task_struct * __t = (task); \
		__t->SYS = (_SYS); \
		__t->run_fn = (_FN); \
		__t->run_env = (_ENV); \
		strncpy(__t->comm, (_COMM), sizeof(__t->comm)); \
		trace_thread("UMC_current_init(%p) from %s comm=%s", __t, FL_STR, __t->comm); \
		__t; \
	    })

#define UMC_current_set(task) \
	    do { \
		struct task_struct * _t = (task); \
		if (_t != NULL) { \
		    assert_eq(current, NULL); \
		    _t->pid = gettid(); \
		    _t->pthread = pthread_self(); \
		} else { \
		    assert(current); \
		} \
		current = _t; \
	    } while (0)

#define UMC_current_free(task) \
	    do { \
		struct task_struct * _t = (task); \
		trace_thread("UMC_current_free(%p) from %s", _t, FL_STR); \
		vfree(_t); \
	    } while (0)

/* Wake up a specific task --
 * Each newly-created task needs a call here to get started.
 * XXX Limitation: only implemented for task startup
 */
#define wake_up_process(task)		kthread_start(task)
#define kthread_start(task)		_kthread_start((task), FL_STR)
extern void _kthread_start(struct task_struct * task, sstring_t whence);

/* Create and initialize a kthread structure -- the pthread is not started yet */
#define kthread_create(fn, env, fmtargs...) \
	    _kthread_create((fn), (env), kasprintf(0, fmtargs), FL_STR)

extern struct task_struct * _kthread_create(error_t (*fn)(void * env),
				void * env, char * name, sstring_t caller_id);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#define kthread_create_on_node(fn, env, node, fmtargs...) \
	    _kthread_create((fn), (env), kasprintf(0, fmtargs))
#endif

/* Create and start a kthread */
#define kthread_run(fn, env, fmtargs...) \
    UMC_kthread_run((fn), (env), kasprintf(0, fmtargs), FL_STR)

extern struct task_struct * UMC_kthread_run(error_t (*fn)(void * env), void * env,
				    char * name, sstring_t caller_id);

extern struct task_struct * UMC_run_shutdown(error_t (*fn)(void * env), void * env);

extern error_t kthread_stop(struct task_struct *);

#define kthread_should_stop()		(current->should_stop)

#define get_task_comm(buf, task)	strncpy((buf), ((task)->comm), TASK_COMM_LEN)

#define task_pid_vnr(task)		((task)->pid)
#define task_pid_nr(task)		((task)->pid)

/* Rename kernel symbol that conflicts with library symbol */
#define sched_setscheduler		UMC_sched_setscheduler

extern error_t UMC_sched_setscheduler(struct task_struct *, int policy, struct sched_param *);

extern error_t set_user_nice(struct task_struct *, int);

/* This can be called on behalf of a new task before the pthread has been created */
#define set_cpus_allowed(task, mask) ( \
	    (task)->cpus_allowed = (mask), \
	    (task)->affinity_is_set = true, \
	    (task)->pid \
		? UMC_kernelize(sched_setaffinity((task)->pid, (int)sizeof(mask), \
						  (cpu_set_t *)&((task)->cpus_allowed))) \
		: 0		     )

#define tsk_cpus_allowed(task)		(&(task)->cpus_allowed)

/******************************************************************************/
/*** Tasklet ***/

// #define UMC_TASKLETS

struct tasklet_struct {
#ifdef UMC_TASKLETS
    spinlock_t			    lock;
    pthread_cond_t		    pcond;
    struct task_struct		  * owner;
    void			  (*fn)(long);
    long			    arg;
    bool		   volatile is_idle;
    bool		   volatile want_run;
    sstring_t			    name;
#endif
};

extern error_t UMC_tasklet_thr(void * v_tasklet);

#ifndef UMC_TASKLETS
#define tasklet_init(x, y, z)		DO_NOTHING()
#define tasklet_schedule(tasklet)	UMC_STUB(tasklet)
#define tasklet_kill(tasklet)		DO_NOTHING()
#else	/* UMC_TASKLETS */

#define tasklet_init(tasklet, fn, arg)	    __tasklet_init((tasklet), (fn), (arg), #fn)
static inline void
__tasklet_init(struct tasklet_struct * tasklet, void (*fn)(long), long arg, sstring_t name)
{
    tasklet->name = name;
    spin_lock_init(&tasklet->lock);
    tasklet->fn = fn;
    tasklet->arg = arg;
    tasklet->is_idle = true;
    pthread_cond_init(&tasklet->pcond, NULL);

    spin_lock(&tasklet->lock);
    tasklet->owner = kthread_run(UMC_tasklet_thr, tasklet, "%s", name);
    sys_buf_allocator_set(tasklet->owner, name);
    spin_unlock(&tasklet->lock);
}

static inline void
tasklet_schedule(struct tasklet_struct * tasklet)
{
    spin_lock(&tasklet->lock);
    tasklet->want_run = true;
    if (tasklet->is_idle) {
	tasklet->is_idle = false;
	pthread_cond_signal(&tasklet->pcond);
    }
    spin_unlock(&tasklet->lock);
}

static inline void
tasklet_kill(struct tasklet_struct * tasklet)
{
    kthread_stop(tasklet->owner);
    pthread_cond_destroy(&tasklet->pcond);
    record_zero(tasklet);
}
#endif

/******************************************************************************/

#define msleep(ms)			usleep((ms) * 1000)
#define jsleep(jiffies)			msleep(jiffies_to_msecs(jiffies))

extern void UMC_alarm_handler(void * v_timer, uint64_t const now, error_t);

struct timer_list {
    void		  (*function)(uintptr_t);   /* kernel-code handler */
    uintptr_t		    data;		    /* kernel-code handler arg */
    uint64_t		    expires;		    /* expiration "jiffy" time */
    sys_alarm_entry_t	    alarm;		    /* non-NULL when alarm pending (ticking) */
};

#define init_timer(timer)		record_zero(timer)
#define timer_pending(timer)		((timer)->alarm != NULL)
#define setup_timer(_timer, _fn, _data)	do { init_timer(_timer);		    \
					     (_timer)->function = (_fn);	    \
					     (_timer)->data = (uintptr_t)(_data);   \
					} while (0)

/* Callable from any thread to cancel a timer -- return true if timer was ticking */
static inline int
del_timer_sync(struct timer_list * timer)
{
    sys_alarm_entry_t alarm = timer->alarm;
    if (alarm == NULL)
	return false;	    /* not pending */

    assert(UMC_irqthread);

    /* sys_alarm_cancel() cancels if possible; otherwise synchronizes with delivery to
     * guarantee the event task thread is not (any longer) executing the handler (for
     * the alarm we tried to cancel) at the time sys_alarm_cancel() returns to us here.
     */
    error_t const err = sys_alarm_cancel(UMC_irqthread->event_task, alarm);

    /* The alarm now either has been cancelled, or its delivery callback has completed
     * (in either case the alarm entry itself has been freed)
     */
    if (!err) {
	timer->alarm = NULL;		/* Cancelled the alarm */
    } else {
	assert_eq(err, EINVAL);		/* alarm entry not found on list */
//	expect_eq(timer->alarm, NULL);	/* UMC_alarm_handler cleared this */ //XXXXX fix this
	timer->alarm = NULL;		//XXXXX timer went off before timer->alarm assigned
    }

    return true;
}

#define del_timer(timer)		del_timer_sync(timer)

#define add_timer(timer)		_add_timer((timer), FL_STR)
static inline void
_add_timer(struct timer_list * timer, sstring_t whence)
{
    assert(UMC_irqthread);
    assert_eq(timer->alarm, NULL);
    assert(timer->function);
    expect_gt(timer->expires, 0, "Adding timer with expiration at time zero");
    //XXXXX BUG: alarm can go off before timer->alarm gets set!
    timer->alarm = sys_alarm_set(UMC_irqthread->event_task,
				 UMC_alarm_handler, timer,
				 jiffies_to_sys_time(timer->expires), whence);
}

static inline void
mod_timer(struct timer_list * timer, uint64_t expire_j)
{
    del_timer_sync(timer);
    timer->expires = expire_j;
    add_timer(timer);
}

#define mod_timer_pending(timer, expire) mod_timer(timer, expire)

/******************************************************************************/
/*** Work queue ***/

/* Has to be embedded in some other state, having no env pointer */
struct work_struct {
    struct list_head		    entry;
    void			  (*fn)(struct work_struct *);
    struct workqueue_struct	  * wq;		    /* for cancel */
    void			  * lockdep_map;    /* unused */
};

#define INIT_WORK(WORK, _fn)		do { INIT_LIST_HEAD(&(WORK)->entry); \
					     (WORK)->fn = (_fn); \
					} while (0)

struct delayed_work {
    struct timer_list	    timer;
    struct work_struct	    work;   /* consumer expects this substructure */
};

#define INIT_DELAYED_WORK(DWORK, _fn)	do { init_timer(&(DWORK)->timer); \
					     INIT_WORK(&(DWORK)->work, (_fn)); \
					} while (0)

/* Process "delayed work" timeout events -- runs on UMC_event_task */
extern void UMC_delayed_work_process(uintptr_t u_dwork);

#define schedule_delayed_work(DWORK, dt_j) \
	    do { setup_timer(&(DWORK)->timer, UMC_delayed_work_process, (DWORK)); \
		 mod_timer(&(DWORK)->timer, sys_time_now() + jiffies_to_sys_time(dt_j)); \
	    } while (0)

#define cancel_delayed_work_sync(DWORK)	del_timer_sync(&(DWORK)->timer)
#define cancel_delayed_work(DWORK)	cancel_delayed_work_sync(DWORK)

struct workqueue_struct {
    struct list_head		    list;
    spinlock_t			    lock;
    struct task_struct		  * owner;
    struct wait_queue_head	    wake;
    struct wait_queue_head	    flushed;
    bool		   volatile is_idle;
    atomic_t			    is_flushing;
    uint64_t			    nenqueued;
    uint64_t			    ndequeued;
    char			    name[64];
};

extern error_t UMC_work_queue_thr(void * v_workq);

extern struct workqueue_struct * create_workqueue(sstring_t name);

#define create_singlethread_workqueue(name)	    create_workqueue(name)

extern void destroy_workqueue(struct workqueue_struct * workq);

#define queue_work(WORKQ, WORK)	\
	    ( !list_empty_careful(&(WORK)->entry) \
		? false	/* already on list */ \
		: ({ bool _do_wake = false; \
		     (WORK)->wq = (WORKQ); \
		     spin_lock(&(WORKQ)->lock); \
		     {   list_add_tail(&(WORK)->entry, &(WORKQ)->list); \
		         ++(WORKQ)->nenqueued; \
			 if (unlikely((WORKQ)->is_idle)) \
			    _do_wake = true; \
		     } \
		     spin_unlock(&(WORKQ)->lock); \
		     if (unlikely(_do_wake)) \
			wake_up(&(WORKQ)->wake); \
		     true;  /* added to list */ }) \
	    )

#define flush_workqueue(WORKQ) \
	    do { spin_lock(&(WORKQ)->lock); \
		 {   atomic_inc(&(WORKQ)->is_flushing); \
		     wake_up(&(WORKQ)->wake); \
		     wait_event_locked((WORKQ)->flushed, \
			   list_empty_careful(_VOLATIZE(&(WORKQ)->list)), lock, (WORKQ)->lock); \
		 } \
		 spin_unlock(&(WORKQ)->lock); \
	    } while (0);

/* Global general-use work queue */
extern struct workqueue_struct * UMC_workq;
#define schedule_work(WORK)		queue_work(UMC_workq, (WORK))
#define flush_scheduled_work()		flush_workqueue(UMC_workq)

//XXXX could do better than this (flush_work)
#define flush_work(WORK) do { \
    if (!list_empty(&(WORK)->entry)) \
	flush_workqueue((WORK)->wq) \
} while (0)

//XXXX could do much better than this (cancel_work_sync)
#define cancel_work_sync(WORK) do { \
    if (!list_empty(&(WORK)->entry)) \
	flush_workqueue((WORK)->wq) \
} while(0)

/******************************************************************************/

extern unsigned int			nr_cpu_ids;

#define raw_smp_processor_id()		sched_getcpu()

static inline unsigned int
smp_processor_id(void)
{
    unsigned int id = raw_smp_processor_id();
    expect_lt(id, nr_cpu_ids);
    return id;
}

#define cpumask_bits(maskp)		((maskp)->bits)
#define cpumask_clear(maskp)		bitmap_zero((maskp), NR_CPUS)
#define cpumask_and(d, s1, s2)		bitmap_and((d)->bits, (s1)->bits, (s2)->bits, NR_CPUS)
#define cpumask_empty(d)		bitmap_empty((d)->bits, NR_CPUS)

#define cpumask_scnprintf(buf, bufsize, mask)	\
	    snprintf((buf), (bufsize), "<0x%016x>", mask.bits[0])

static inline int
_cpumask_test_cpu(int cpu, cpumask_t *cpumask)
{
    return _bitmap_test_bit(cpumask_bits(cpumask), cpu);
}

/* The cpumask_var_t is stored directly in the pointer, not allocated; so max 64 CPUs */
typedef cpumask_t			cpumask_var_t[1];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)

#define nr_cpumask_bits			nr_cpu_ids

static inline void
free_cpumask_var(cpumask_var_t mask)
{
    /* NOP */
}

static inline void
cpumask_copy(cpumask_t *dstp, const cpumask_t *srcp)
{
    bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

static inline void
cpumask_setall(cpumask_t *dstp)
{
    bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline bool
cpumask_equal(const cpumask_t *src1p, const cpumask_t *src2p)
{
    return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p), nr_cpumask_bits);
}

static inline bool
alloc_cpumask_var(cpumask_var_t *mask, gfp_t gfp)
{
    assert_static(NR_CPUS <= BITS_PER_LONG);
    return true;
}

static inline bool
zalloc_cpumask_var(cpumask_var_t *mask, gfp_t gfp)
{
    bool ok = alloc_cpumask_var(mask, gfp);
    if (ok)
	record_zero(mask);
    return ok;
}

static inline unsigned int
cpumask_next(int n, const cpumask_t *srcp)
{
    return (unsigned int)find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

static inline void
cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
    _bitmap_set_bit(cpumask_bits(dstp), cpu);
}

static inline int
cpumask_test_cpu(int cpu, cpumask_t *cpumask)
{
    return _cpumask_test_cpu(cpu, cpumask);
}

#endif

static inline bool
cpu_online(int cpun)
{
    cpu_set_t cpuset;
    int rc = sched_getaffinity(getpid(), sizeof(cpuset), &cpuset);
    if (rc)
	return 0;
    return _cpumask_test_cpu(cpun, (cpumask_t *)&(cpuset));
}

static inline int
num_online_cpus(void)
{
    cpu_set_t cpuset;
    //XXX maybe this is supposed to be system CPUs, not this thread's
    int rc = sched_getaffinity(getpid(), sizeof(cpuset), &cpuset);
    if (rc)
	return 0;
    return CPU_COUNT(&cpuset);
}

#define NUMA_NO_NODE			(-1)
#define cpu_to_node(cpu)		(0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)

#define for_each_cpu(cpu, mask)				    \
	    for ((cpu) = cpumask_next(-1, (mask));	    \
		    (cpu) = cpumask_next((cpu), (mask)),    \
		    (cpu) < nr_cpu_ids;)

#define for_each_online_cpu(cpu)    for_each_cpu(cpu, tsk_cpus_allowed(current))    //XXX Right?

#define set_cpus_allowed_ptr(task, maskp) set_cpus_allowed((task), *(maskp))

#endif

#define in_softirq()			false //XXX (sys_event_task_current() != NULL)
#define in_atomic()			false
#define in_irq()			false	/* never in hardware interrupt */
#define in_interrupt()			(in_irq() || in_softirq())

#define need_resched()			false
#define cond_resched()			DO_NOTHING()	//XXXX OK?

#endif /* UMC_THREAD_H */
