#include "ft_strace.h"

t_st_config	g_cfg = { 0 };

static void	config_cleanup(void)
{
	if (g_cfg.pid_table)
		free(g_cfg.pid_table);
}

void	set_signals(void)
{
	sigset_t	empty;
	sigset_t	blocked;

	if (sigemptyset(&empty))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigprocmask(SIG_SETMASK, &empty, NULL))
		err(EXIT_FAILURE, "sigprocmask");
	if (sigemptyset(&blocked))
		err(EXIT_FAILURE, "sigemptyset");
	if (sigaddset(&blocked, SIGHUP) || sigaddset(&blocked, SIGINT)
		|| sigaddset(&blocked, SIGQUIT) || sigaddset(&blocked, SIGPIPE)
		|| sigaddset(&blocked, SIGTERM))
		err(EXIT_FAILURE, "sigaddset");
}

int	main(int argc, char **argv)
{
	char		**args = NULL;

	g_cfg.output = stderr;
	program_invocation_name = program_invocation_short_name;
	args = parse_options(&g_cfg, argc, argv);
	if (atexit(config_cleanup))
		error(EXIT_FAILURE, 0, "cannot set exit function");
	if (!*args && !g_cfg.pid_table)
		error(EXIT_FAILURE, 0, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);
	set_signals();

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

	if (!g_cfg.process_count)
		return (EXIT_FAILURE);
	process_event_loop(&g_cfg);

	return (EXIT_SUCCESS);
}
