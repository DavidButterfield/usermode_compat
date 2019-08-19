/* UMC_lock.h -- Usermode compatibility: barriers, atomics, locking, refcounting
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#include "UMC_thread.h"	/* include above the _H guard */

#ifndef UMC_LOCK_H
#define UMC_LOCK_H
#include <stddef.h>	// container_of, offsetof   //XXX
#include <pthread.h>	//XXXXXX remove after fixing to use sys_mutex, not pthread_mutex
#include <semaphore.h>	//XXX could move this to .c file

#define trace_lock(args...)	//	nlprintk(args)

#define UMC_LOCK_CHECKS	    /* do lock checks in all builds */

#define __barrier()			__sync_synchronize()
#define smp_mb()			__barrier()
#define smp_rmb()			__barrier()
#define smp_wmb()			__barrier()

#define	smp_mb__before_atomic_dec()	__barrier()
#define	smp_mb__after_atomic_dec()	__barrier()
#define	smp_mb__after_atomic_inc()	__barrier()

#define ATOMIC_INIT(n)			((atomic_t){ .counter = (n) })

					//XXXX Figure out which of these barriers isn't needed
#define atomic_get(ptr)			({ __barrier(); int ag_ret = (ptr)->counter; __barrier(); ag_ret; })
#define atomic_set(ptr, val)		do { __barrier(); (ptr)->counter = (val); __barrier(); } while (0)

#define atomic_read(ptr)		atomic_get(ptr)

/* Bitwise atomics return the OLD value */
#define atomic_or(n, ptr)		__sync_fetch_and_or( &(ptr)->counter, (n))
#define atomic_and(n, ptr)		__sync_fetch_and_and(&(ptr)->counter, (n))

/* Arithmetic atomics return the NEW value */
#define atomic_add_return(n, ptr)	__sync_add_and_fetch(&(ptr)->counter, (n))
#define atomic_sub_return(n, ptr)	__sync_sub_and_fetch(&(ptr)->counter, (n))
#define atomic_inc_return(ptr)		atomic_add_return(1, (ptr))
#define atomic_dec_return(ptr)		atomic_sub_return(1, (ptr))

#define atomic_add(n, ptr)		atomic_add_return((n), (ptr))
#define atomic_sub(n, ptr)		atomic_sub_return((n), (ptr))
#define atomic_inc(ptr)			atomic_inc_return(ptr)
#define atomic_dec(ptr)			atomic_dec_return(ptr)

/* These return true if result *IS* zero */
#define atomic_dec_and_test(ptr)	(!atomic_dec_return(ptr))
#define atomic_sub_and_test(n, ptr)	(!atomic_sub_return((n), (ptr)))

/* Installs the new value at addr and returns the old value */
#define xchg(addr, newv) ({ \
	    typeof(*addr) ____newv = (newv); \
	    typeof(*addr) ____oldv; \
	    __atomic_exchange((addr), &(____newv), &(____oldv), __ATOMIC_SEQ_CST); \
	    ____oldv; \
})

#define atomic_xchg(atom, newv) xchg(&(atom)->counter, (newv))

/* Installs the new value at addr if and only if the old value matches */
/* Either way, it returns the old value as it was prior to the instruction */
#define cmpxchg(addr, oldv, newv) \
		__sync_val_compare_and_swap((addr), (oldv), (newv))

#define atomic_cmpxchg(atom, oldv, newv) \
		cmpxchg(&(atom)->counter, (oldv), (newv))

static inline bool
_atomic_cas(atomic_t * atomic, int const expected, int const newval)
{
    return __sync_bool_compare_and_swap(&atomic->counter, expected, newval);
}

static inline int
atomic_add_unless(atomic_t * ptr, int increment, int unless_match)
{
    int oldval;
    do {
	oldval = atomic_get(ptr);
	if (unlikely(oldval == unless_match))
	    break;
    } while (!_atomic_cas(ptr, oldval, oldval + increment));

    return oldval;
}

/********** Locks **********/

#if defined(__i386__) || defined(__x86_64__)
    /* Avoid clogging CPU pipeline with lock fetches for several times around a spinloop */
    /* There seems to be some problem with valgrind long looping with this instruction XXX */
    #include <valgrind.h>
    #define _SPINWAITING()   do { if (!RUNNING_ON_VALGRIND) __builtin_ia32_pause(); } while (0)
#else
  #define _SPINWAITING()		/* */
#endif

/*** Multi-Reader/Single-Writer SPIN lock -- favors readers, recursive read OK ***/
typedef struct rwlock {
    atomic_t			count;	/* units available to take */
    struct task_struct * volatile owner; /* exclusive holder (writer), if any */
    sstring_t			name;	/* logging string */
} rwlock_t;

#define _RWLOCK_FMT		"name=%s owner=%p[%u]%s count=%d"
#define _RWLOCK_FIELDS(RW)	(RW)->name, (RW)->owner, (RW)->owner?(RW)->owner->tid:0, \
				(RW)->owner?(RW)->owner->name:"", atomic_read(&(RW)->count)

/* (1<<16) can support up to 64K concurrent readers and 32K contending writers */
#define _RW_LOCK_WR_COUNT		(1UL<<16)   /* count required for writing */
#define _RW_LOCK_RD_COUNT		1	    /* count required for reading */

#define RW_LOCK_UNLOCKED(rwname)	{ .count = { _RW_LOCK_WR_COUNT }, .name = #rwname }
#define DEFINE_RWLOCK(rw)		struct rwlock rw = RW_LOCK_UNLOCKED(#rw)
#define rwlock_init(rw)			(*(rw) = (rwlock_t)RW_LOCK_UNLOCKED(#rw))

static inline void
rwlock_assert_writer(rwlock_t * rw)
{
#ifdef UMC_LOCK_CHECKS
    verify_le(atomic_read(&rw->count), 0,
		    "Writer not locked exclusive??");
    verify_eq(current, rw->owner,
		    "%s expected to own lock '%s' owned instead by %s",
		    current->comm, rw->name, rw->owner->comm);
#endif
}

static inline void
rwlock_assert_readlocked(rwlock_t * rw)
{
#ifdef UMC_LOCK_CHECKS
    expect_lt(atomic_read(&rw->count), _RW_LOCK_WR_COUNT,
		"%s is not locked from writes as expected", rw->name);
    expect_gt(atomic_read(&rw->count), 0,
		"%s is WRITE locked during read assertion", rw->name);
#endif
}

/* Try to take ntake units from rwlock->count --
 * Returns true if ntake acquired, else false (and zero count taken)
 */
static inline bool
rwlock_take_try(rwlock_t * rw, unsigned int ntake)
{
    /* Try to take the requested count */
    if (unlikely(atomic_sub_return(ntake, &rw->count) < 0)) {
	/* Overdraft -- insufficient count available to satisfy "take" request */
	atomic_add(ntake, &rw->count);	/* give back our overdraft of rw->count */
#ifdef UMC_LOCK_CHECKS
	expect_ne(rw->owner, current,
		"Thread attempts to acquire a rw_spinlock it already holds for WRITE");
#endif
	return false;
    }
    /* Successfully took (ntake) from lock available count */
#ifdef UMC_LOCK_CHECKS
    verify_eq(rw->owner, NULL);	    /* we got it, so nobody else better own it exclusively */
#endif
    if (ntake >= _RW_LOCK_WR_COUNT) {
	/* We're not merely reading -- record as exclusive owner */
	rw->owner = current;
    }
    trace_lock("'%s' (%u) takes %u for %s from spinlock %s at %p",
	  current->comm, current->pid,
	  ntake, ntake >= _RW_LOCK_WR_COUNT ? "WRITE" : "READ", rw->name, rw);
    return true;
}

#define read_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_RD_COUNT)
#define write_lock_try(rw)		rwlock_take_try((rw), _RW_LOCK_WR_COUNT)

#define read_lock(rw)		do { while (!read_lock_try(rw)) _SPINWAITING(); } while (0)
#define write_lock(rw)		do { while (!write_lock_try(rw)) _SPINWAITING(); } while (0)

static inline void
rwlock_drop(rwlock_t * rw, unsigned int ndrop)
{
    trace_lock("'%s' (%u) returns %u (%s) to spinlock %s at %p",
	  current->comm, current->pid,
	  ndrop, ndrop >= _RW_LOCK_WR_COUNT ? "WRITE" : "READ", rw->name, rw);
    if (unlikely(ndrop >= _RW_LOCK_WR_COUNT)) {
	rwlock_assert_writer(rw);
	rw->owner = NULL;
    }
#ifdef UMC_LOCK_CHECKS
    int new_count = atomic_add_return(ndrop, &rw->count);
    verify_le(new_count, _RW_LOCK_WR_COUNT, "too many unlocks?");
#else
    atomic_add(ndrop, &rw->count);
#endif
}

#define read_unlock(rw)			rwlock_drop((rw), _RW_LOCK_RD_COUNT)
#define write_unlock(rw)		rwlock_drop((rw), _RW_LOCK_WR_COUNT)
#define write_downgrade(rw)		rwlock_drop((rw), (_RW_LOCK_WR_COUNT-_RW_LOCK_RD_COUNT))

/* Lock alone should suffice because the usermode softirq thread is never (virtually) "local" */
#define write_lock_bh(rw)		write_lock(rw)
#define write_unlock_bh(rw)		write_unlock(rw)

/* Lock alone should suffice here in usermode */
#define read_lock_irq(rw)		read_lock(rw)
#define read_unlock_irq(rw)		read_unlock(rw)
#define read_lock_irqsave(rw, irq)	read_lock(rw)
#define read_unlock_irqrestore(rw, irq)	do { _USE(irq); read_unlock(rw); } while (0)

#define write_lock_irq(rw)		write_lock(rw)
#define write_unlock_irq(rw)		write_unlock(rw)
#define write_lock_irqsave(rw, irq)	write_lock(rw)
#define write_unlock_irqrestore(rw, irq) do { _USE(irq); write_unlock(rw); } while (0)

/*** Sleepable mutex lock -- also used for spinlock mutex using _trylock() ***/

#define MUTEX_UNLOCKED(m)		((struct mutex){ .lock = PTHREAD_MUTEX_INITIALIZER, .name = #m })
#define DEFINE_MUTEX(m)			struct mutex m = MUTEX_UNLOCKED(#m)
#define mutex_init(m)			do { *(m) = MUTEX_UNLOCKED(#m); } while (0)
#define mutex_destroy(m)		pthread_mutex_destroy(&(m)->lock)

static inline void
mutex_assert_holding(struct mutex * lock)
{
#ifdef UMC_LOCK_CHECKS
    verify_eq(current, lock->owner,
		"%s (%d) expected to own lock '%s' owned instead by %s (%d) taken at %s",
		current->comm, current->pid, lock->name,
		lock->owner->comm, lock->owner->pid, lock->last_locker);
#endif
}

#ifdef UMC_LOCK_CHECKS

#define UMC_LOCK_CLAIM(lock, whence) do { \
    verify_eq((lock)->owner, NULL); \
    (lock)->owner = current; \
    (lock)->last_locker = whence; \
    trace_lock("'%s' (%u) at %s takes lock %s (@%p)", \
	current->comm, current->pid, whence, lock->name, lock); \
} while (0)

#define UMC_LOCK_DISCLAIM(lock, whence) do { \
    trace_lock("'%s' (%u) at %s drops lock %s (@%p)", \
	    current->comm, current->pid, whence, lock->name, lock); \
    mutex_assert_holding(lock); \
    (lock)->owner = NULL; \
} while (0)

#else

#define UMC_LOCK_CLAIM(lock, whence) \
    trace_lock("'%s' (%u) at %s takes lock %s (@%p)", \
	    current->comm, current->pid, whence, lock->name, lock); \

#define UMC_LOCK_DISCLAIM(lock, whence) \
    trace_lock("'%s' (%u) at %s drops lock %s (@%p)", \
	    current->comm, current->pid, whence, lock->name, lock); \

#endif

/* Try to acquire a mutex lock -- returns true if lock acquired, false if not */
#define mutex_trylock(lock)		(_mutex_trylock((lock), FL_STR) == 0)

/* Returns 0 if lock acquired */
static inline error_t
_mutex_trylock(struct mutex * lock, sstring_t whence)
{
    error_t err = pthread_mutex_trylock(&lock->lock);
    if (unlikely(err)) {
	if (err != EBUSY)
	    pr_warning("Error %s (%d) on pthread_mutex_trylock(%s) from %s\n",
		    strerror(err), err, lock->name, whence);
	return -err;
    }
    UMC_LOCK_CLAIM(lock, whence);
    return 0;
}

/* Avoid a pair of context switches when wait time is short */
static inline error_t
_mutex_tryspin(struct mutex * lock, sstring_t whence)
{
    #define MUTEX_SPINS 100	/* Try this many spins before resorting to context switch */
    uint32_t spins = MUTEX_SPINS;
    while (spins--) {
	error_t err;
	if (likely((err = _mutex_trylock(lock, whence)) == 0))
	    return 0;	/* got the lock */
	_SPINWAITING();
    }
    return -EBUSY;
}

/* Acquire a mutex lock */
#define mutex_lock(lock)		_mutex_lock((lock), FL_STR)
static inline void
_mutex_lock(struct mutex * lock, sstring_t whence)
{
    error_t err = _mutex_tryspin(lock, whence);
    if (!err)
	return;
#ifdef UMC_LOCK_CHECKS
    verify(lock->owner != current,
	"Thread %d ('%s') attempts to acquire a lock '%s' (@%p) "
	"it already holds (%p) taken at %s",
	current->pid, current->comm,
	lock->name, lock, lock->owner, lock->last_locker);
#endif
    /* We exhausted the time we're willing to spinwait -- give up the CPU */
    pthread_mutex_lock(&lock->lock);	/* sleep */
    UMC_LOCK_CLAIM(lock, whence);
}

/* Returns 0 if mutex acquired; otherwise -EINTR on signal */
#define mutex_lock_interruptible(lock)	_mutex_lock_interruptible((lock), FL_STR)

static inline void
mutex_unlock(struct mutex * lock)
{
    UMC_LOCK_DISCLAIM(lock, whence);
    pthread_mutex_unlock(&lock->lock);
}

/* Use of this function is inherently racy */
static inline bool
mutex_is_locked(struct mutex * lock)
{
    if (unlikely(!mutex_trylock(lock))) {
	return true;	/* we couldn't get the mutex, therefore it is locked */
    }
    mutex_unlock(lock);    /* unlock the mutex we just locked to test it */
    return false;	/* We got the mutex, therefore it was not locked */
}

/*** Mutex SPIN lock ***/
#define DEFINE_SPINLOCK(lock)		DEFINE_MUTEX(lock)
#define SPINLOCK_UNLOCKED(m)		{ .lock = PTHREAD_MUTEX_INITIALIZER, .name = #m }
#define spin_lock_init(lock)		mutex_init(lock)
#define spin_lock_destroy(lock)		(no one ever destroys a spinlock)

#define assert_spin_locked(lock)	mutex_assert_holding(lock)
#define spin_lock_assert_holding(lock)	mutex_assert_holding(lock)

/* Different from mutex to implement nested spinlock */
#define spin_lock_try(lock)		_spin_lock_try(lock, FL_STR)
/* Returns 0 if lock acquired */
static inline error_t
_spin_lock_try(struct mutex * lock, sstring_t whence)
{
    error_t err = pthread_mutex_trylock(&lock->lock);
    if (unlikely(err)) {
	if (err != EBUSY)
	    pr_warning("Error %s (%d) on pthread_mutex_trylock(%s) from %s\n",
		    strerror(err), err, lock->name, whence);
	return -err;
    }
    if (atomic_read(&lock->nest)) {
	pthread_mutex_unlock(&lock->lock);
	return -EBUSY;
    }
    UMC_LOCK_CLAIM(lock, whence);
    return 0;
}

/* Unlike _mutex_lock, this function only spins on _trylock(), never sleeps */
#define spin_lock(lock)			_spin_lock((lock), FL_STR)
static inline void
_spin_lock(spinlock_t * lock, sstring_t whence)
{
    error_t err;
    while ((err = _spin_lock_try(lock, whence)) != 0) {
#ifdef UMC_LOCK_CHECKS
	verify(lock->owner != current,
	    "Thread %d ('%s') attempts to acquire a lock '%s' (@%p) "
	    "it already holds (%p) taken at %s",
	    current->pid, current->comm,
	    lock->name, lock, lock->owner, lock->last_locker);
#endif
	_SPINWAITING();
    }
}

/* Unlock a spinlock */
#define spin_unlock(lock)		_spin_unlock(lock, FL_STR)
static inline void
_spin_unlock(spinlock_t * lock, sstring_t whence)
{
    if (!atomic_add_unless(&lock->nest, -1, 0))
	mutex_unlock(lock);
}

/* Use of this function is inherently racy */
static inline bool
spinlock_is_locked(spinlock_t * lock)
{
    if (unlikely(!spin_lock_try(lock))) {
	return true;	/* we couldn't get the lock, therefore it is locked */
    }
    spin_unlock(lock);  /* unlock the lock we just locked to test it */
    return false;	/* We got the lock, therefore it was not locked */
}

/* Takes a spinlock even if it is already held */
#define spin_lock_nested(lock, subclass)    _spin_lock_nested((lock), (subclass), FL_STR)
static inline void
_spin_lock_nested(spinlock_t * lock, int subclass, sstring_t whence)
{
    atomic_inc(&lock->nest);

    /* Try hard for a legitimate take of the lock by spinwaiting a short time.
     * If we can get it, we don't need to "nest".
     */
    if (_mutex_tryspin(lock, whence) == 0)
	atomic_dec(&lock->nest);
}

extern int _atomic_dec_and_lock(atomic_t * atomic, spinlock_t * lock);
#define atomic_dec_and_lock(atomic, lock) _atomic_dec_and_lock(atomic, lock)

/* Lock by itself should suffice */
#define spin_lock_bh(lock)		spin_lock(lock)
#define spin_lock_irq(lock)		spin_lock(lock)
#define spin_lock_irqsave(lock, save)	do { _USE(save); spin_lock(lock); } while (0)

#define spin_lock_bh_assert_holding(l)	spin_lock_assert_holding(l)
#define spin_lock_irq_assert_holding(l)	spin_lock_assert_holding(l)

#define spin_unlock_bh(lock)		spin_unlock(lock)
#define spin_unlock_irq(lock)		spin_unlock(lock)
#define spin_unlock_irqrestore(lock, save)  spin_unlock(lock)

/* "local" functions shouldn't need to do anything more than the associated lock accomplishes */
#define local_bh_disable()		DO_NOTHING()
#define local_bh_enable()		DO_NOTHING()
#define local_irq_save(saver)		DO_NOTHING( _USE(saver) )
#define local_irq_restore(saver)	DO_NOTHING()
#define local_irq_disable()		DO_NOTHING()
#define local_irq_enable()		DO_NOTHING()
#define irqs_disabled()			false

#define preempt_disable()		DO_NOTHING()
#define preempt_enable()		DO_NOTHING()

/* Lock held checks */
#define lockdep_assert_held(lock)	assert_eq(current, (lock)->owner)
#define lockdep_is_held(lock)		(current == (lock)->owner)

/* Lockdep not implemented */
struct lock_class_key { };
struct lockdep_map { };
#define STATIC_LOCKDEP_MAP_INIT(name, key)		{ }
#define lockdep_set_class(a, b)				DO_NOTHING()
#define rwlock_acquire_read(map, subclass, trylock, IP)	DO_NOTHING()
#define lock_contended(map, IP)				DO_NOTHING()
#define lock_acquired(map, IP)				DO_NOTHING()
#define rwlock_release(map, n, IP)			DO_NOTHING()

#define __acquires(x)			/* */
#define __releases(x)			/* */
#define __acquire(x)			(void)0
#define __release(x)			(void)0

/*** RCU Synchronization (faked using rw_lock) ***/

extern error_t UMC_rcu_cb_fn(void * unused);

extern rwlock_t				UMC_rcu_lock;	/* the global pseudo-RCU lock */

/* Embedded in each RCU-protected structure */
struct rcu_head {
    void				* next;
    void				(*func)(struct rcu_head *);
};

/* Readers */
#define rcu_read_lock()			read_lock(&UMC_rcu_lock)
#define rcu_read_unlock()		read_unlock(&UMC_rcu_lock)
#define _rcu_assert_readlocked()	rwlock_assert_readlocked(&UMC_rcu_lock)

/* These are only supposed to be used under rcu_read_lock(), right? XXX */
#define rcu_dereference(ptr)		({ /* _rcu_assert_readlocked(); */ (ptr); })

#define list_for_each_entry_rcu(p, h, m) /* _rcu_assert_readlocked(); */ \
					 list_for_each_entry((p), (h), m)

#define rcu_dereference_protected(p, c) ({ assert(c); (p); })

/* Writers */
#define UMC_rcu_write_lock()		write_lock(&UMC_rcu_lock)
#define UMC_rcu_write_unlock()		write_unlock(&UMC_rcu_lock)

#define rcu_assign_pointer(ptr, val)	do { UMC_rcu_write_lock(); \
					     (ptr) = (val); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_add_rcu(elem, list)	do { UMC_rcu_write_lock(); \
					     list_add(elem, list); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_add_tail_rcu(elem, list)	do { UMC_rcu_write_lock(); \
					     list_add_tail(elem, list); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define list_del_rcu(elem)		do { UMC_rcu_write_lock(); \
					     list_del(elem); \
					     UMC_rcu_write_unlock(); \
					} while (0)

extern struct rcu_head		      * UMC_rcu_cb_list;
extern spinlock_t			UMC_rcu_cb_list_lock;
extern struct task_struct	      * UMC_rcu_cb_thr;

#define call_rcu(head, fn)		do { (head)->func = fn; \
					     spin_lock(&UMC_rcu_cb_list_lock); \
					     (head)->next = UMC_rcu_cb_list; \
					     if (!UMC_rcu_cb_list) \
						wake_up(&UMC_rcu_cb_wake); \
					     UMC_rcu_cb_list = (head); \
					     spin_unlock(&UMC_rcu_cb_list_lock); \
					} while (0)

#define synchronize_rcu()		do { UMC_rcu_write_lock(); \
					     UMC_rcu_write_unlock(); \
					} while (0)

#define __rcu				/* neutralize some kernel compiler thing */

/*** Sleepable semaphore ***/

#define trace_sema(fmtargs...)	//	sys_trace(fmtargs)

struct semaphore {
    sem_t				UM_sem;
    struct task_struct       * volatile owner;
    sstring_t				last_locker;
};

static inline error_t
sema_init(struct semaphore * sem, unsigned int val)
{
    return UMC_kernelize(sem_init(&sem->UM_sem, 0/*intra-process*/, val));
}

#define up(sem) UMC_up((sem), FL_STR)
static inline error_t
UMC_up(struct semaphore * sem, sstring_t whence)
{
    sem->owner = NULL;
    error_t err = UMC_kernelize(sem_post(&sem->UM_sem));
    trace_sema("%s: ++++++++++ UP(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
    return err;
}

#define down(sem) UMC_down((sem), FL_STR)
static inline error_t
UMC_down(struct semaphore * sem, sstring_t whence)
{
    trace_sema("%s: ========== DOWN(%p) %d-->...", whence, sem, *(int *)sem);
    error_t err = UMC_kernelize(sem_wait(&sem->UM_sem));
    trace_sema("%s: ---------- DOWN(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
    sem->owner = current;
    sem->last_locker = whence;
    return err;
}

#define down_trylock(sem) UMC_down_trylock((sem), FL_STR)
static inline error_t
UMC_down_trylock(struct semaphore * sem, sstring_t whence)
{
    error_t err = UMC_kernelize(sem_trywait(&sem->UM_sem));
    if (!err) {
	trace_sema("%s: ---------- DOWN_TRY(%p)-->%d err=%d", whence, sem, *(int *)sem, err);
	sem->owner = current;
	sem->last_locker = whence;
    } else {
	trace_sema("%s: xxxxxxxxxx DOWN_TRY(%p)==%d err=%d", whence, sem, *(int *)sem, err);
    }
    return err;
}

/*** kref ***/

struct kref {
    atomic_t refcount;
};

#define kref_trace(args...)    //	sys_trace(args)

#define kref_init(kref)			_kref_init((kref), FL_STR)
static inline void
_kref_init(struct kref *kref, sstring_t caller_id)
{
    atomic_set(&(kref)->refcount, 1);
    kref_trace("%s: KREF_INIT %p", caller_id, (void *)kref);
}

#define kref_get(kref)			_kref_get((kref), FL_STR)
static inline void
_kref_get(struct kref *kref, sstring_t caller_id)
{
    int nrefs = atomic_inc_return(&(kref)->refcount);
    assert_ge(nrefs, 2);
    kref_trace("%s: KREF_GET %p increases refs to %d", caller_id, (void *)kref, nrefs);
}

#define kref_put(kref, destructor)	_kref_put((kref), (destructor), FL_STR)
static inline int
_kref_put(struct kref *kref, void (*destructor)(struct kref *), sstring_t caller_id)
{
    int nrefs = atomic_read(&(kref)->refcount);
    assert_gt(nrefs, 0);

    if (!atomic_dec_and_test(&(kref)->refcount)) {
	kref_trace("%s: KREF_PUT %p leaves %d refs remaining", caller_id, (void *)kref, nrefs-1);
	return false;
    }

    kref_trace("%s: KREF_PUT %p calls destructor", caller_id, (void *)kref);
    destructor(kref);
    return true;
}

#define kref_read(kref) (atomic_read(&(kref)->refcount))

/*** kobj ***/

struct attribute {
    const char		  * name;
    umode_t		    mode;
    void		  * owner;
};

struct kobject {
    struct kref		kref;
    struct list_head    entry;
    char	      * name;
    struct kobj_type  * ktype;
    struct kobject    * parent;
};

struct kobj_type {
    void  (*release)(struct kobject *);
    struct sysfs_ops const * sysfs_ops;
    struct attribute	 ** default_attrs;
    ssize_t (*show)(struct kobject *kobj, struct attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);
};

struct kobj_attribute {
    struct attribute attr;
    ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
};

#define __ATTR(_name, _mode, _show, _store) {			    \
    .attr = { .name = __stringify(_name), .mode = _mode },	    \
    .show   = _show,						    \
    .store  = _store,						    \
}

#define _kobject_init(kobj, type)	do { record_zero(kobj);		    \
					     kref_init(&(kobj)->kref);	    \
					     (kobj)->ktype = (type);	    \
					     INIT_LIST_HEAD(&(kobj)->entry);\
					} while (0)

/* type argument was added to kobject_init() in 2.6.25 */
#define kobject_init(kobj, type...)	_kobject_init((kobj), type+0)

static inline void
kobject_release(struct kref * kref)
{
    struct kobject * kobj = container_of(kref, struct kobject, kref);
    kobj->ktype->release(kobj);
}

static inline void
kobject_put(struct kobject * kobj)
{
    if (kobj)
	kref_put(&kobj->kref, kobject_release);
}

static inline void
kobject_get(struct kobject * kobj)
{
    kref_get(&kobj->kref);
}

#define kobject_uevent(a, b)		(UMC_size_t_JUNK=0)
#define KOBJ_CHANGE			IGNORED

#endif /* UMC_LOCK_H */
