#include "ft_strace.h"
#include <string.h>

static void	print_signal(t_st_config *cfg,
	unsigned int sig, unsigned int stopped, siginfo_t *siginfo)
{
	//TODO: pass siginfo_t to print more info about signals
	if (!stopped && siginfo)
		stprintf(cfg, "--- SIG%s [TODO: more info] ---\n",
			sigabbrev_np(sig));
	else
		stprintf(cfg, "--- stopped by SIG%s ---\n", sigabbrev_np(sig));
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
		stopped = (ptrace(PTRACE_GETSIGINFO, cfg->current_pid, NULL, &siginfo) < 0);
		print_signal(cfg, sig, stopped, stopped ? NULL : &siginfo);
	}

	if (stopped && ptrace(PTRACE_LISTEN, cfg->current_pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");
	else if (!stopped && ptrace(PTRACE_SYSCALL, cfg->current_pid, NULL, sig) < 0)
		err(EXIT_FAILURE, "ptrace");
}

void	process_event_loop(t_st_config *cfg)
{
	int				status = -1;

	while (cfg->process_count)
	{
		if ((cfg->current_pid = waitpid(-1, &status, __WALL)) <= 0)
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
			stprintf(cfg, "+++ killed by SIG%s +++\n",
				sigabbrev_np(WTERMSIG(status)));
			--cfg->process_count;
		} else if (!WIFSTOPPED(status)) {
			error(0, 0, "waitpid: unknown status %x", status);
			--cfg->process_count;
		} else
			handle_stopped_process(cfg, status);
	}
}
