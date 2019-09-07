/* UMC_time.h -- usermode compatibility for time
 *
 * Copyright 2019 David A. Butterfield
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#ifndef UMC_TIME_H
#define UMC_TIME_H

extern struct timezone sys_tz;

static inline struct timespec
ns_to_timespec(unsigned long ns)
{
    struct timespec ts = { };
    ts.tv_sec  = (long)(ns / 1000000000ul);
    ts.tv_nsec = (long)(ns % 1000000000ul);
    return ts;
}

static inline struct timeval
ns_to_timeval(unsigned long ns)
{
    struct timespec ts = ns_to_timespec(ns);
    struct timeval tv;
    tv.tv_sec = ts.tv_sec;
    tv.tv_usec = ts.tv_nsec / 1000;
    return tv;
}

#define NSEC_PER_USEC			1000L
#define NSEC_PER_MSEC			1000000L
#define NSEC_PER_SEC			1000000000L
#define USEC_PER_SEC			1000000L
#include "include/linux/ktime.h"

#define ktime(t)			((ktime_t){ .tv64 = (t) })
#define ktime_get()			ktime(sys_time_now() / (sys_time_hz()/1000000000L))
#define ktime_get_real() ({ \
    struct timespec _t;							\
    clock_gettime(CLOCK_REALTIME, &_t);					\
    ktime(_t.tv_sec*1L*1000*1000*1000 + _t.tv_nsec);			\
})

#define jiffies				( sys_time_now() / (sys_time_hz()/HZ) )

#define SYS_TIME_MAX			((unsigned long)LONG_MAX)
#define JIFFY_MAX			INT_MAX

#define msecs_to_jiffies(ms)		((unsigned long)(ms) * HZ / (1000))

#define jiffies_of_sys_time(t)		( (unsigned long)(t) / (sys_time_hz()/HZ) )

#define jiffies_to_sys_time(j) \
	    ( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
								* sys_time_hz() / HZ )

#define jiffies_to_msecs(j) \
	    (int)( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
								* 1000ul / HZ )

#define jiffies_to_usecs(j) \
	    ( (((unsigned long)(j) > JIFFY_MAX) ? JIFFY_MAX : (unsigned long)(j)) \
							       * 1000ul * 1000ul / HZ )

#define sys_time_abs_of_jdelta(jdelta) \
({ \
    sys_time_t now = sys_time_now(); \
    sys_time_t _t_end = now + jiffies_to_sys_time(jdelta); \
    if (time_before(_t_end, now)) \
	_t_end = SYS_TIME_MAX; /* overflow */ \
    _t_end; \
})

//XXXX Check all these time comparisons wrt signed vs. unsigned, and overflow
#define time_after(x, y)		((long)((x) - (y)) > 0)
#define time_after_eq(x, y)		((long)((x) - (y)) >= 0)
#define time_before(x, y)		time_after((y), (x))
#define time_before_eq(x, y)		time_after_eq((y), (x))

/* Who thought it was a good idea to declare the kernel version of tm.tm_year as type long?? */
/* Kernel version from include/linux/time.h */
struct tm {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        long tm_year;
        int tm_wday;
        int tm_yday;
};

/* libc version from x86_64-linux-gnu/bits/types/struct_tm.h */
struct tm_libc			/* ISO C `broken-down time' structure.  */
{
	int tm_sec;		/* Seconds.     [0-60] (1 leap second) */
	int tm_min;		/* Minutes.     [0-59] */
	int tm_hour;		/* Hours.       [0-23] */
	int tm_mday;		/* Day.         [1-31] */
	int tm_mon;		/* Month.       [0-11] */
	int tm_year;		/* Year - 1900.  */
	int tm_wday;		/* Day of week. [0-6] */
	int tm_yday;		/* Days in year.[0-365] */
	int tm_isdst;		/* DST.         [-1/0/1]*/
	long int tm_gmtoff;	/* Seconds east of UTC.  */
	const char *tm_zone;	/* Timezone abbreviation.  */
};

static inline void
time_to_tm(time_t secs, int ofs, struct tm * result)
{
    time_t total = secs + ofs;
    struct tm_libc tm_libc;
    localtime_r(&total, (void *)&tm_libc);  /* ugh */
    result->tm_sec =	    tm_libc.tm_sec;
    result->tm_min =	    tm_libc.tm_min;
    result->tm_hour =	    tm_libc.tm_hour;
    result->tm_mday =	    tm_libc.tm_mday;
    result->tm_mon =	    tm_libc.tm_mon;
    result->tm_year = (long)tm_libc.tm_year;
    result->tm_wday =	    tm_libc.tm_wday;
    result->tm_yday =	    tm_libc.tm_yday;
}

#endif /* UMC_TIME_H */
