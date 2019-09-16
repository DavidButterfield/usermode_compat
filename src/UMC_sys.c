/* UMC_sys.c
 * Compatibility for kernel code running in usermode
 * Copyright 2016-2019 David A. Butterfield
 */
#define _GNU_SOURCE
#include "UMC_sys.h"
#include <sys/wait.h>

struct module UMC_module = { .name = "UMC", .version = "1.1" };

struct timezone sys_tz;

__thread size_t UMC_size_t_JUNK = 0;	/* for avoiding unused-value gcc warnings */

void
dump_stack(void)
{
    sys_backtrace("call to dump_stack()");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int
__ratelimit(struct ratelimit_state *rs)
{
    return 1;	    /* no ratelimit */
}
#endif

uint32_t crc32c_uniq;	//XXX hack makes these unique -- fake is no good for matching

extern int sysinfo(struct sysinfo *);

/******************************************************************************/

/* Call (another) usermode program */
int
call_usermodehelper(const char * progpath, char * argv[], char * envp[], int waitflag)
{
    pid_t cpid = fork();
    if (cpid < 0) {
	printk("usermodehelper '%s' fork failed!\n", progpath);
	return -1;
    }
    if (cpid) {
	int status;
	if (waitflag == UMH_NO_WAIT)
	    return 0;

	waitpid(cpid, &status, 0);
	if (!WIFEXITED(status))
	    printk("usermodehelper '%s' abnormal exit\n", progpath);
	else if (WEXITSTATUS(status))
	    printk("usermodehelper '%s' exit code %u\n", progpath, WEXITSTATUS(status));
	else
	    return 0;

	return -1;
    }
    execve(progpath, argv, envp);
    printk("usermodehelper '%s' not found\n", progpath);
    exit(99);
}

void
si_meminfo(struct sysinfo *si)
{
    struct sysinfo si_space;
    int rc = sysinfo(&si_space);
    expect_noerr(rc, "sysinfo");
    /* Kernel code appears to assume the unit is PAGE_SIZE */
    unsigned int unit = si_space.mem_unit;
    si->totalram = si_space.totalram * unit / PAGE_SIZE;
    si->totalhigh = si_space.totalhigh * unit / PAGE_SIZE;
}

/******************************************************************************/

char *
UMC_string_concat_free(char * prefix, char * suffix)
{
    char * str;

    if (!suffix)
	return prefix;
    if (!prefix)
	return suffix;

    str = kasprintf(0, "%s%s", prefix, suffix);

    vfree(prefix);
    vfree(suffix);
    return str;
}

char *
strnchr(const char * str, size_t strmax, int match)
{
    while (strmax && *str) {
	if (*str == match)
	    return _unconstify(str);
	++str;
	--strmax;
    }
    return NULL;	/* not found */
}

unsigned long
simple_strtoul(const char * str, char ** endptr, unsigned int base)
{
    return strtoul(str, endptr, base);
}

//XXX strict_strtoul() is not as strict as it ought to be

error_t
strict_strtoul(const char * str, unsigned int base, unsigned long * var)
{
    errno = 0;
    unsigned long val = strtoul(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return 0;
}

error_t
strict_strtoull(const char * str, unsigned int base, unsigned long long * var)
{
    errno = 0;
    unsigned long long val = strtoull(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return 0;
}

error_t
strict_strtol(const char * str, unsigned int base, long * var)
{
    errno = 0;
    long val = strtol(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return 0;
}

error_t
strict_strtoll(const char * str, unsigned int base, long long * var)
{
    errno = 0;
    long long val = strtoll(str, NULL, base);
    if (errno)
	return -errno;
    *var = val;
    return 0;
}

/******************************************************************************/
/* Not used with the tcmur storage backends, but we still need the symbols */

#ifdef ENABLE_AIO
extern __thread char sys_pthread_name[16];
#endif

/* Callback when an AIO thread is created to set up a "current" pointer for it --
 * the AIO thread calls back into "kernel" code which expects this
 */
extern void aios_thread_init(void * unused);
void
aios_thread_init(void * unused)
{
#ifdef ENABLE_AIO
    expect_eq(unused, NULL);
    UMC_current_set(
	    UMC_current_init(
		    UMC_current_alloc(),
		    sys_thread_current(),
		    (void *)aios_thread_init,
		    unused,
		    kstrdup(sys_pthread_name, IGNORED)));

    error_t err = pthread_setname_np(pthread_self(), sys_pthread_name);
    expect_noerr(err, "pthread_setname_np");
#else
    panic("reached %s", __func__);
#endif
}

extern void aios_thread_exit(void * unused);
void
aios_thread_exit(void * unused)
{
#ifdef ENABLE_AIO
    expect_eq(unused, NULL);
    assert(current);
    UMC_current_free(current);
    UMC_current_set(NULL);
#else
    panic("reached %s", __func__);
#endif
}
