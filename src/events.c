#include "ft_strace.h"
#include <string.h>

static void	print_signal(unsigned int sig, unsigned int stopped)
{
	//TODO: pass siginfo_t to print more info about signals
	if (!stopped)
		printf("--- SIG%s [TODO: more info] ---\n", sigabbrev_np(sig));
	else
		printf("--- stopped by SIG%s ---\n", sigabbrev_np(sig));
}

static void	handle_stopped_process(pid_t pid, int status)
{
	siginfo_t		siginfo;
	unsigned int	stopped = 0, sig = WSTOPSIG(status),
					event = (unsigned int)status >> 16;

	if (sig == (SIGTRAP | 0x80)) {
		printf("syscall() = ?\n"); //TEMP
		sig = 0;
	} else if (event) {
		if (event == PTRACE_EVENT_STOP && (sig == SIGSTOP || sig == SIGTSTP
			|| sig == SIGTTIN || sig == SIGTTOU))
		{
			stopped = 1;
			print_signal(sig, stopped);
		} else {
			//TODO: See how to handle this case when nothing is printed because
			//we already printed the pid in case of multiple processes. Will
			//probably need to move the pid printing to right before the output.
			sig = 0;
		}
	} else {
		stopped = (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) < 0);
		print_signal(sig, stopped);
	}

	if (stopped && ptrace(PTRACE_LISTEN, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");
	else if (!stopped && ptrace(PTRACE_SYSCALL, pid, NULL, sig) < 0)
		err(EXIT_FAILURE, "ptrace");
}

void	process_event_loop(t_st_config *cfg)
{
	pid_t			pid;
	int				status = -1;

	while (cfg->process_count)
	{
		if ((pid = waitpid(-1, &status, __WALL)) <= 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}

		if (cfg->process_count > 1)
			printf("[pid %5u] ", pid);
		if (WIFEXITED(status)) {
			printf("+++ exited with %d +++\n", WEXITSTATUS(status));
			--cfg->process_count;
		} else if (WIFSIGNALED(status)) {
			printf("+++ killed by SIG%s +++\n", sigabbrev_np(WTERMSIG(status)));
			--cfg->process_count;
		} else if (!WIFSTOPPED(status)) {
			error(0, 0, "waitpid: unknown status %x", status);
			--cfg->process_count;
		} else
			handle_stopped_process(pid, status);
	}
}
