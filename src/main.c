#include "ft_strace.h"

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
			if (!trace_process(g_cfg.pid_table[i]))
				++g_cfg.process_count;
	}

	if (*args)
	{
		char	*command = find_command(*args);

		if (!command && !g_cfg.process_count)
			exit(EXIT_FAILURE);
		else if (command)
		{
			execute_command(command, args);
			++g_cfg.process_count;
		}
	}

	int		status = -1;
	pid_t	pid;
	while (g_cfg.process_count)
	{
		if ((pid = waitpid(-1, &status, __WALL)) < 0)
		{
			if (errno == EINTR)
				continue ;
			err(EXIT_FAILURE, "waitpid");
		}

		printf("[%d] ", pid);
		if (WIFEXITED(status)) {
			printf("exited, status=%d\n", WEXITSTATUS(status));
			--g_cfg.process_count;
		} else if (WIFSIGNALED(status)) {
			printf("killed by signal %d\n", WTERMSIG(status));
			--g_cfg.process_count;
		} else if (WIFSTOPPED(status)) {
			printf("stopped by signal %d\n", WSTOPSIG(status));
			if (WSTOPSIG(status) == (SIGTRAP | 0x80)
				&& ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
				err(EXIT_FAILURE, "ptrace");
		} else if (WIFCONTINUED(status)) {
			printf("continued\n");
		}
	}

	return (EXIT_SUCCESS);
}
