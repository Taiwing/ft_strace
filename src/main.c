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
		pid_t	command_pid;
		char	*command = find_command(*args);

		if (!command)
			exit(EXIT_FAILURE);
		command_pid = execute_command(command, args);
		printf("command_pid = %d\n", command_pid);
	}

	int		status;
	pid_t	pid;
	do
	{
		if ((pid = waitpid(-1, &status, __WALL)) < 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}

		if (WIFEXITED(status)) {
			printf("exited, status=%d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			printf("killed by signal %d\n", WTERMSIG(status));
		} else if (WIFSTOPPED(status)) {
			printf("stopped by signal %d\n", WSTOPSIG(status));
			if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
				err(EXIT_FAILURE, "ptrace");
		} else if (WIFCONTINUED(status)) {
			printf("continued\n");
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	return (EXIT_SUCCESS);
}
