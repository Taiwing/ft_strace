#include "ft_strace.h"
#include <sys/wait.h>
#include <sys/ptrace.h>

t_st_config	g_cfg = { 0 };

static void	config_cleanup(void)
{
	if (g_cfg.pid_table)
		free(g_cfg.pid_table);
}

int	main(int argc, char **argv)
{
	char		**args = NULL;

	program_invocation_name = program_invocation_short_name;
	args = parse_options(&g_cfg, argc, argv);
	if (atexit(config_cleanup))
		error(EXIT_FAILURE, 0, "cannot set exit function");
	if (!*args && !g_cfg.pid_table)
		error(EXIT_FAILURE, 0, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);
	if (g_cfg.pid_table)
	{
		for (size_t i = 0; i < g_cfg.pid_table_size; ++i)
			printf("pid_table[%zu] = %d\n", i, g_cfg.pid_table[i]);
	}
	if (*args)
	{
		pid_t	pid;
		char	*command = find_command(*args);

		if (!command)
			exit(EXIT_FAILURE);

		pid = fork();
		switch (pid)
		{
			case -1:
				free(command);
				err(EXIT_FAILURE, "fork");
			case 0:
				printf("child pid = %d\n", getpid());
				printf("toto\n");
				if (raise(SIGSTOP))
				{
					free(command);
					err(EXIT_FAILURE, "raise");
				}
				if (execvp(command, args) < 0)
				{
					free(command);
					err(EXIT_FAILURE, "'%s'", *args);
				}
				break;
			default:
				free(command);
				int status;
				while (waitpid(pid, &status, WUNTRACED) < 0) {
					if (errno != EINTR)
						err(EXIT_FAILURE, "waitpid");
				}
				if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
					kill(pid, SIGKILL);
					err(EXIT_FAILURE, "child did not stop");
				}
				printf("parent pid = %d\n", getpid());
				if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0)
					err(EXIT_FAILURE, "ptrace");
				if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
					err(EXIT_FAILURE, "ptrace");
				if (kill(pid, SIGCONT) < 0)
					err(EXIT_FAILURE, "kill");
				while (waitpid(pid, &status, WUNTRACED) < 0) {
					if (errno != EINTR)
						err(EXIT_FAILURE, "waitpid");
				}
				if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
					kill(pid, SIGKILL);
					err(EXIT_FAILURE, "child did not stop at execve()");
				}
				exit(EXIT_SUCCESS);
		}
		//printf("%s", *args++);
		//while (*args)
		//	printf(" %s", *args++);
		//putchar('\n');
	}
	return (EXIT_SUCCESS);
}
