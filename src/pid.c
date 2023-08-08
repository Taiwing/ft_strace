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

	// Set PTRACE_O_TRACESYSGOOD so that we can distinguish between
	// a syscall induced event and a normal SIGTRAP.
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) < 0)
		err(EXIT_FAILURE, "ptrace");

	// Trace the process and resume execution.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	return (0);
}

size_t	parse_pid_list(pid_t *dest, char *pid_argument)
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
		dest[size++] = pid;
	}
	if (!size)
		error(EXIT_FAILURE, EINVAL, "%s: '%s'", __func__, pid_argument);
	return (size);
}
