#define _GNU_SOURCE
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <string.h>

int	main(void)
{
	int		ret;
	pid_t	pid;

    if ((pid = syscall(SYS_getpid)) < 0)
		err(EXIT_FAILURE, "getpid");
	else
		printf("pid: %d\n", pid);

	errno = 0;
	ret = syscall(SYS_create_module);
	if (errno)
		warn("create_module");
	else if (ret < 0)
		warnx("create_module: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_set_thread_area);
	if (errno)
		warn("set_thread_area");
	else if (ret < 0)
		warnx("set_thread_area: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_get_thread_area);
	if (errno)
		warn("get_thread_area");
	else if (ret < 0)
		warnx("get_thread_area: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_modify_ldt);
	if (errno)
		warn("modify_ldt");
	else if (ret < 0)
		warnx("modify_ldt: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_arch_prctl);
	if (errno)
		warn("arch_prctl");
	else if (ret < 0)
		warnx("arch_prctl: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_iopl);
	if (errno)
		warn("iopl");
	else if (ret < 0)
		warnx("ioctl: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	errno = 0;
	ret = syscall(SYS_rt_sigreturn, NULL);
	if (errno)
		warn("rt_sigreturn");
	else if (ret < 0)
		warnx("ioctl: %s", strerror(-ret));
	printf("ret: %d\n", ret);

	return (EXIT_SUCCESS);
}
