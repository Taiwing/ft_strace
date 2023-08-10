#include "ft_strace.h"

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
	t_st_config	cfg = {0};
	char		**args = NULL, *command;

	program_invocation_name = program_invocation_short_name;
	args = parse_options(&cfg, argc, argv);
	if (!*args && !cfg.process_table_size)
		errx(EXIT_FAILURE, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);
	set_signals();

	for (size_t i = 0; i < cfg.process_table_size; ++i)
		if (!trace_process(cfg.process_table[i].pid))
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
			cfg.process_table[cfg.process_table_size++].pid =
				execute_command(command, args);
			++cfg.running_processes;
		}
	}

	if (!cfg.running_processes)
		return (EXIT_FAILURE);
	process_event_loop(&cfg);

	return (EXIT_SUCCESS);
}
