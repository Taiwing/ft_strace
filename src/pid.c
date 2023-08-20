#include "ft_strace.h"
#include <string.h>

t_st_process	*find_process(t_st_config *cfg, pid_t pid)
{
	for (size_t i = 0; i < cfg->process_table_size; ++i)
		if (cfg->process_table[i].pid == pid)
			return (cfg->process_table + i);
	return (NULL);
}

int				trace_process(t_st_config *cfg, pid_t pid)
{
	int	status;

	// Seize and interrupt running process.
	if (ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD) < 0)
	{
		if (errno == ESRCH || errno == EPERM)
		{
			warn("ptrace");
			return (-1);
		}
		err(EXIT_FAILURE, "ptrace");
	}
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	// Wait for the process to stop.
	st_waitpid(cfg, pid, &status, WUNTRACED);
	if (!WIFSTOPPED(status))
		error(EXIT_FAILURE, 0, "process did not stop");

	// Resume execution.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	return (0);
}

size_t			parse_pid_list(t_st_process *dest, char *pid_argument)
{
	pid_t		pid = 0;
	size_t		size = 0;
	char		*tok = NULL, *tail = NULL;

	if (!pid_argument)
		error(EXIT_FAILURE, EINVAL, __func__);
	for (tok = strtok(pid_argument, ", "); tok; tok = strtok(NULL, ", "))
	{
		if (size == MAX_PROCESS)
			error(EXIT_FAILURE, E2BIG, "%s", __func__);
		errno = 0;
		pid = (pid_t)strtol(tok, &tail, 0);
		if (pid < 0 || tail == tok || *tail != '\0')
			error(EXIT_FAILURE, EINVAL, "%s: '%s'", __func__, tok);
		dest[size++].pid = pid;
	}
	if (!size)
		error(EXIT_FAILURE, EINVAL, "%s: '%s'", __func__, pid_argument);
	return (size);
}
