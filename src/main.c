#include "ft_strace.h"

t_st_config	*g_cfg;

int	main(int argc, char **argv)
{
	t_st_config	cfg = {0};
	char		**args = NULL, *command;

	g_cfg = &cfg;
	cfg.child_pid = -1;
	program_invocation_name = program_invocation_short_name;
	args = parse_options(&cfg, argc, argv);
	if (!*args && !cfg.process_table_size)
		errx(EXIT_FAILURE, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);

	for (size_t i = 0; i < cfg.process_table_size; ++i)
		if (!trace_process(&cfg, cfg.process_table[i].pid))
		{
			warnx("Process %u attached", cfg.process_table[i].pid);
			++cfg.running_processes;
		}

	if (*args)
	{
		if (cfg.process_table_size == MAX_PROCESS)
			errx(EXIT_FAILURE, "too many processes (max %d)", MAX_PROCESS);
		else if ((command = find_command(*args)))
		{
			cfg.child_pid = execute_command(&cfg, command, args);
			cfg.process_table[cfg.process_table_size++].pid = cfg.child_pid;
			++cfg.running_processes;
		}
	}

	if (!cfg.running_processes)
		return (EXIT_FAILURE);
	set_signals(&cfg.blocked);
	process_event_loop(&cfg);

	return (EXIT_SUCCESS);
}
