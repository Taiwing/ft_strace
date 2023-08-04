#include "ft_strace.h"
#include <sys/wait.h>
#include <sys/ptrace.h>

static void	trace_child(pid_t pid)
{
	int status;

	// Wait for the child to stop.
	while (waitpid(pid, &status, WUNTRACED) < 0)
		if (errno != EINTR)
			err(EXIT_FAILURE, "waitpid");
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		kill(pid, SIGKILL);
		error(EXIT_FAILURE, 0, "child did not stop");
	}

	// Trace the child.
	if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");

	// Resume child execution.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
		err(EXIT_FAILURE, "ptrace");
}

__attribute__((noreturn))
static void	child_process(char *command, char **argv)
{
	// Stop the child process so that the parent can trace it.
	if (raise(SIGSTOP))
	{
		free(command);
		err(EXIT_FAILURE, "raise");
	}

	// Execute the given command.
	execvp(command, argv);

	// Only reached if execvp() failed.
	free(command);
	err(EXIT_FAILURE, "'%s'", *argv);
}

pid_t		execute_command(char *command, char **argv)
{
	pid_t	pid = fork();

	if (pid < 0)
	{
		free(command);
		err(EXIT_FAILURE, "fork");
	}
	else if (pid == 0)
		child_process(command, argv);
	else
	{
		free(command);
		trace_child(pid);
	}
	return (pid);
}
