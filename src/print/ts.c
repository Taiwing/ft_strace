#include "ft_strace.h"

const struct timespec	g_ts_zero = { 0, 0 };

void	ts_add(struct timespec *dest, const struct timespec *src)
{
	dest->tv_sec += src->tv_sec;
	dest->tv_nsec += src->tv_nsec;
	if (dest->tv_nsec >= NSEC_PER_SEC)
	{
		dest->tv_sec += src->tv_nsec / NSEC_PER_SEC;
		dest->tv_nsec %= NSEC_PER_SEC;
	}
}

void	ts_sub(struct timespec *dest, const struct timespec *src)
{
	dest->tv_sec -= src->tv_sec;
	if (dest->tv_nsec < src->tv_nsec)
	{
		dest->tv_sec -= 1;
		dest->tv_nsec += NSEC_PER_SEC;
	}
	dest->tv_nsec -= src->tv_nsec;
}

int		ts_cmp(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return (a->tv_sec - b->tv_sec);
	return (a->tv_nsec - b->tv_nsec);
}

void timeval_to_timespec(struct timespec *dest, const struct timeval *src)
{
	dest->tv_sec = src->tv_sec;
	dest->tv_nsec = src->tv_usec * NSEC_PER_USEC;
	if (dest->tv_nsec >= NSEC_PER_SEC)
	{
		dest->tv_sec += dest->tv_nsec / NSEC_PER_SEC;
		dest->tv_nsec %= NSEC_PER_SEC;
	}
}
