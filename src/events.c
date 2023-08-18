#include "ft_strace.h"

pid_t		st_waitpid(t_st_config *cfg, pid_t pid, int *status, int options)
{
	pid_t	ret;

	unblock_signals();
	while ((ret = waitpid(pid, status, options)) < 0 && errno == EINTR);
	if (ret < 0)
		err(EXIT_FAILURE, "waitpid");
	block_signals(&cfg->blocked);
	return (ret);
}

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
		pid = st_waitpid(cfg, -1, &status, __WALL);
		if (!(process = find_process(cfg, pid)))
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
			cfg->current_process->running = 0;
			--cfg->running_processes;
			if (cfg->current_process == cfg->child_process)
				cfg->exit_code = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			if (cfg->current_process->in_syscall)
				stprintf(NULL, " <unfinished ...>\n");
			stprintf(cfg, "+++ killed by %s %s+++\n", signame(WTERMSIG(status)),
				WCOREDUMP(status) ? "(core dumped) " : "");
			cfg->current_process->running = 0;
			--cfg->running_processes;
			if (cfg->current_process == cfg->child_process)
				cfg->exit_code = 128 + WTERMSIG(status);
		} else if (WIFSTOPPED(status))
			handle_stopped_process(cfg, status);
		else
			errx(EXIT_FAILURE, "waitpid: unknown status %x", status);
	}
}
