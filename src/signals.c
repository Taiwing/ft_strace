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

void		unblock_signals(void)
{
	sigset_t	empty;

	if (sigemptyset(&empty))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigprocmask(SIG_SETMASK, &empty, NULL))
		err(EXIT_FAILURE, "sigprocmask");
}

void		block_signals(sigset_t *blocked)
{
	if (sigprocmask(SIG_BLOCK, blocked, NULL))
		err(EXIT_FAILURE, "sigprocmask");
}

static void	sigint_handler(int sig)
{
	if (g_cfg->child_process && g_cfg->child_process->running)
		kill(g_cfg->child_process->pid, sig);
	else
		exit(0x80 | sig);
}

void		set_signals(sigset_t *blocked)
{
	if (sigemptyset(blocked))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigaddset(blocked, SIGHUP) || sigaddset(blocked, SIGINT)
		|| sigaddset(blocked, SIGQUIT) || sigaddset(blocked, SIGPIPE)
		|| sigaddset(blocked, SIGTERM))
		err(EXIT_FAILURE, "sigaddset");
	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		err(EXIT_FAILURE, "signal");
}
