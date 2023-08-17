#include "ft_strace.h"

static void	handle_stopped_process(t_st_config *cfg, int status)
{
	siginfo_t		siginfo;
	unsigned int	stopped = 0, sig = WSTOPSIG(status),
					event = (unsigned int)status >> 16;

	if (sig == (SIGTRAP | 0x80)) {
		get_syscall(cfg->current_process);
		print_syscall(cfg);
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
		stopped = (ptrace(PTRACE_GETSIGINFO, cfg->current_process->pid,
			NULL, &siginfo) < 0);
		print_signal(cfg, sig, stopped, stopped ? NULL : &siginfo);
	}

	if (stopped
		&& ptrace(PTRACE_LISTEN, cfg->current_process->pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");
	else if (!stopped
		&& ptrace(PTRACE_SYSCALL, cfg->current_process->pid, NULL, sig) < 0)
		err(EXIT_FAILURE, "ptrace");
}

void		process_event_loop(t_st_config *cfg)
{
	pid_t			pid;
	t_st_process	*process;
	int				status = -1;

	while (cfg->running_processes)
	{
		if ((pid = waitpid(-1, &status, __WALL)) <= 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}
		else if (!(process = find_process(cfg, pid)))
			errx(EXIT_FAILURE, "waitpid: unknown pid %d", pid);
		else if (cfg->current_process && cfg->current_process != process
			&& cfg->current_process->in_syscall)
		{
			stprintf(NULL, " <unfinished ...>\n");
			cfg->current_process->interrupted_syscall = 1;
		}
		cfg->current_process = process;

		if (WIFEXITED(status)) {
			if (cfg->current_process->in_syscall)
				print_syscall(cfg);
			stprintf(cfg, "+++ exited with %d +++\n", WEXITSTATUS(status));
			--cfg->running_processes;
		} else if (WIFSIGNALED(status)) {
			if (cfg->current_process->in_syscall)
				stprintf(NULL, " <unfinished ...>\n");
			stprintf(cfg, "+++ killed by %s +++\n", signame(WTERMSIG(status)));
			--cfg->running_processes;
		} else if (WIFSTOPPED(status))
			handle_stopped_process(cfg, status);
		else
			errx(EXIT_FAILURE, "waitpid: unknown status %x", status);
	}
}
