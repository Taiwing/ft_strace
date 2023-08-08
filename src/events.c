#include "ft_strace.h"

static void	print_signal(t_st_config *cfg,
	unsigned int sig, unsigned int stopped, siginfo_t *si)
{
	if (!stopped && si)
	{
		if (si->si_code == SI_USER)
			stprintf(cfg, "--- %s {si_signo=%s, si_code=SI_USER, si_pid=%d,"
				" si_uid=%d} ---\n", signame(sig), signame(si->si_signo),
				si->si_pid, si->si_uid);
		else if (si->si_code == SI_KERNEL)
			stprintf(cfg, "--- %s {si_signo=%s, si_code=SI_KERNEL} ---\n",
				signame(sig), signame(si->si_signo));
		else
			stprintf(cfg, "--- %s {si_signo=%s, si_code=%d, si_pid=%d,"
				" si_uid=%d} ---\n", signame(sig), signame(si->si_signo),
				si->si_code, si->si_pid, si->si_uid);
	}
	else
		stprintf(cfg, "--- stopped by %s ---\n", signame(sig));
}

static void	handle_stopped_process(t_st_config *cfg, int status)
{
	siginfo_t		siginfo;
	unsigned int	stopped = 0, sig = WSTOPSIG(status),
					event = (unsigned int)status >> 16;

	if (sig == (SIGTRAP | 0x80)) {
		stprintf(cfg, "syscall() = ?\n"); //TEMP
		sig = 0;
	} else if (event) {
		if (event == PTRACE_EVENT_STOP && (sig == SIGSTOP || sig == SIGTSTP
			|| sig == SIGTTIN || sig == SIGTTOU))
		{
			stopped = 1;
			print_signal(cfg, sig, stopped, NULL);
		} else {
			sig = 0;
		}
	} else {
		stopped = (ptrace(PTRACE_GETSIGINFO, cfg->current_process, NULL, &siginfo) < 0);
		print_signal(cfg, sig, stopped, stopped ? NULL : &siginfo);
	}

	if (stopped && ptrace(PTRACE_LISTEN, cfg->current_process, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");
	else if (!stopped && ptrace(PTRACE_SYSCALL, cfg->current_process, NULL, sig) < 0)
		err(EXIT_FAILURE, "ptrace");
}

void	process_event_loop(t_st_config *cfg)
{
	int				status = -1;

	while (cfg->process_count)
	{
		if ((cfg->current_process = waitpid(-1, &status, __WALL)) <= 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}

		if (WIFEXITED(status)) {
			stprintf(cfg, "+++ exited with %d +++\n",
				WEXITSTATUS(status));
			--cfg->process_count;
		} else if (WIFSIGNALED(status)) {
			stprintf(cfg, "+++ killed by %s +++\n", signame(WTERMSIG(status)));
			--cfg->process_count;
		} else if (!WIFSTOPPED(status)) {
			error(0, 0, "waitpid: unknown status %x", status);
			--cfg->process_count;
		} else
			handle_stopped_process(cfg, status);
	}
}
