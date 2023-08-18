#include "ft_strace.h"

void	unblock_signals(void)
{
	sigset_t	empty;

	if (sigemptyset(&empty))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigprocmask(SIG_SETMASK, &empty, NULL))
		err(EXIT_FAILURE, "sigprocmask");
}

void	block_signals(sigset_t *blocked)
{
	if (sigprocmask(SIG_BLOCK, blocked, NULL))
		err(EXIT_FAILURE, "sigprocmask");
}

void	set_blocked_signals(sigset_t *blocked)
{
	if (sigemptyset(blocked))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigaddset(blocked, SIGHUP) || sigaddset(blocked, SIGINT)
		|| sigaddset(blocked, SIGQUIT) || sigaddset(blocked, SIGPIPE)
		|| sigaddset(blocked, SIGTERM))
		err(EXIT_FAILURE, "sigaddset");
}
