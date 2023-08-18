#include "ft_strace.h"

t_st_config	*g_cfg;

int	main(int argc, char **argv)
{
	t_st_config	cfg = {0};
	char		**args = NULL, *command;

	g_cfg = &cfg;
	program_invocation_name = program_invocation_short_name;
	args = parse_options(&cfg, argc, argv);
	if (!*args && !cfg.process_table_size)
		errx(EXIT_FAILURE, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);

	for (size_t i = 0; i < cfg.process_table_size; ++i)
		if (!trace_process(&cfg, cfg.process_table[i].pid))
		{
			warnx("Process %u attached", cfg.process_table[i].pid);
			cfg.process_table[i].running = 1;
			++cfg.running_processes;
		}

	if (*args)
	{
		if (cfg.process_table_size == MAX_PROCESS)
			errx(EXIT_FAILURE, "too many processes (max %d)", MAX_PROCESS);
		else if ((command = find_command(*args)))
		{
			pid_t	pid = execute_command(&cfg, command, args);
			cfg.child_process = cfg.process_table + cfg.process_table_size++;
			cfg.child_process->pid = pid;
			cfg.child_process->running = 1;
			++cfg.running_processes;
		}
	}

	if (!cfg.running_processes)
		return (EXIT_FAILURE);
	set_signals(&cfg.blocked);
	process_event_loop(&cfg);

	// Child process exited with a signal, replicate it
	if (cfg.exit_code > 128)
	{
		cfg.exit_code -= 128;
		signal(cfg.exit_code, SIG_DFL);
		raise(cfg.exit_code);
		cfg.exit_code += 128;
	}

	return (cfg.exit_code);
}
