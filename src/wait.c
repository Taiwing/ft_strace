#include "ft_strace.h"

static void	process_stopped(t_st_config *cfg, int status)
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

static void	process_killed(t_st_config *cfg, int status)
{
	if (cfg->current_process->in_syscall
		&& !cfg->current_process->interrupted)
		stprintf(NULL, " <unfinished ...>\n");
	stprintf(cfg, "+++ killed by %s %s+++\n", signame(WTERMSIG(status)),
		WCOREDUMP(status) ? "(core dumped) " : "");
	cfg->current_process->running = 0;
	--cfg->running_processes;
	if (cfg->current_process == cfg->child_process)
		cfg->exit_code = 0x100 | WTERMSIG(status);
}

static void	process_exited(t_st_config *cfg, int status)
{
	if (cfg->current_process->in_syscall)
		print_syscall(cfg);
	stprintf(cfg, "+++ exited with %d +++\n", WEXITSTATUS(status));
	cfg->current_process->running = 0;
	--cfg->running_processes;
	if (cfg->current_process == cfg->child_process)
		cfg->exit_code = WEXITSTATUS(status);
}

static void	set_current_process(t_st_config *cfg, pid_t pid)
{
	t_st_process	*process;

	if (!(process = find_process(cfg, pid)))
		errx(EXIT_FAILURE, "waitpid: unknown pid %d", pid);
	else if (cfg->current_process && cfg->current_process != process
		&& cfg->current_process->in_syscall)
	{
		stprintf(NULL, " <unfinished ...>\n");
		cfg->current_process->interrupted = 1;
	}
	cfg->current_process = process;
}

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

void		wait_processes(t_st_config *cfg)
{
	pid_t			pid;
	int				status = -1;

	while (cfg->running_processes)
	{
		pid = st_waitpid(cfg, -1, &status, __WALL);
		set_current_process(cfg, pid);

		if (WIFEXITED(status))
			process_exited(cfg, status);
		else if (WIFSIGNALED(status))
			process_killed(cfg, status);
		else if (WIFSTOPPED(status))
			process_stopped(cfg, status);
		else
			errx(EXIT_FAILURE, "waitpid: unknown status %x", status);
	}
}
