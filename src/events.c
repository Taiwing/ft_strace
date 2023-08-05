#include "ft_strace.h"
#include <string.h>

void	process_event_loop(t_st_config *cfg)
{
	int		status = -1;
	pid_t	pid;

	while (cfg->process_count)
	{
		if ((pid = waitpid(-1, &status, __WALL)) < 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}

		if (cfg->process_count > 1)
			printf("[%d] ", pid);
		if (WIFEXITED(status)) {
			printf("+++ exited with %d +++\n", WEXITSTATUS(status));
			--cfg->process_count;
		} else if (WIFSIGNALED(status)) {
			printf("+++ killed by SIG%s +++\n", sigabbrev_np(WTERMSIG(status)));
			--cfg->process_count;
		} else if (WIFSTOPPED(status)) {
			printf("--- stopped by SIG%s ---\n", sigabbrev_np(WSTOPSIG(status)));
			if (WSTOPSIG(status) == (SIGTRAP | 0x80)
				&& ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
				err(EXIT_FAILURE, "ptrace");
		} else if (WIFCONTINUED(status)) {
			printf("continued\n");
		}
	}
}
