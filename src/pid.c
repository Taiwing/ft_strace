#include "ft_strace.h"
#include <string.h>

int		trace_process(pid_t pid)
{
	int	status;

	// Seize running process.
	if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0)
	{
		if (errno == ESRCH || errno == EPERM)
		{
			warn("ptrace");
			return (-1);
		}
		err(EXIT_FAILURE, "ptrace");
	}

	// Interrupt process.
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	// Wait for the process to stop.
	while (waitpid(pid, &status, WUNTRACED) < 0)
		if (errno != EINTR)
			err(EXIT_FAILURE, "waitpid");
	if (!WIFSTOPPED(status))
		error(EXIT_FAILURE, 0, "process did not stop");

	// Trace the process.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	return (0);
}

size_t	parse_pid_list(pid_t **dest, char *pid_argument)
{
	static size_t	size = 0;
	size_t			ret = 0;
	pid_t			pid = 0;
	char			*token = NULL, *tail = NULL;

	if (!size && (!pid_argument || !(token = strtok(pid_argument, ", "))))
		error(EXIT_FAILURE, EINVAL, __func__);
	else if (!size || !!(token = strtok(pid_argument, ", ")))
	{
		errno = 0;
		pid = (pid_t)strtol(token, &tail, 0);
		if (pid < 0 || tail == token || *tail != '\0')
			error(EXIT_FAILURE, EINVAL, "%s: '%s'", __func__, token);
		size += 1;
		ret = parse_pid_list(dest, NULL);
		(*dest)[--size] = pid;
	}
	else if (!(*dest = malloc(size * sizeof(pid_t))))
		err(EXIT_FAILURE, __func__);
	else
		ret = size;
	return (ret);
}
