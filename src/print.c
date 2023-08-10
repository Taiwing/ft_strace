#include "ft_strace.h"
#include <string.h>
#include <signal.h>

char	*signame(int sig)
{
	int			ret;
	static char	buf[32];
	const char	*abbrev = sigabbrev_np(sig);

	if (abbrev)
		ret = snprintf(buf, sizeof(buf), "SIG%s", abbrev);
	else if (sig == SIGRTMIN)
		ret = snprintf(buf, sizeof(buf), "SIGRTMIN");
	else if (sig > SIGRTMIN && sig <= SIGRTMAX)
		ret = snprintf(buf, sizeof(buf), "SIGRT_%d", sig - SIGRTMIN);
	else
		ret = snprintf(buf, sizeof(buf), "Unknown Signal %d", sig);
	return (ret < 0 ? NULL : buf);
}

int	stprintf(t_st_config *cfg, const char *format, ...)
{
	va_list		args;
	int			ret;

	if (cfg && cfg->running_processes > 1)
		fprintf(stderr, "[pid %5u] ", cfg->current_process->pid);
	va_start(args, format);
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return (ret);
}
