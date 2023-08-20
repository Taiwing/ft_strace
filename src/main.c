#include "ft_strace.h"

t_st_config	*g_cfg;

static void	attach_running_processes(t_st_config *cfg)
{
	for (size_t i = 0; i < cfg->process_table_size; ++i)
		if (!trace_process(cfg, cfg->process_table[i].pid))
		{
			warnx("Process %u attached", cfg->process_table[i].pid);
			cfg->process_table[i].running = 1;
			++cfg->running_processes;
		}
}

static void	spawn_child_process(t_st_config *cfg, char **args)
{
	pid_t	pid;
	char	*command;

	if (cfg->process_table_size == MAX_PROCESS)
		errx(EXIT_FAILURE, "too many processes (max %d)", MAX_PROCESS);
	else if ((command = find_command(*args)))
	{
		pid = execute_command(cfg, command, args);
		cfg->child_process = cfg->process_table + cfg->process_table_size++;
		cfg->child_process->pid = pid;
		cfg->child_process->running = 1;
		++cfg->running_processes;
	}
	else
		warnx("'%s': command not found", *args);
}

void		terminate(void)
{
	if (g_cfg->summary)
	{
		stprintf(NULL, "\n");
		print_summary(g_cfg);
	}
	if (g_cfg->exit_code > 0xff)
	{
		g_cfg->exit_code &= 0xff;
		signal(g_cfg->exit_code, SIG_DFL);
		raise(g_cfg->exit_code);
		g_cfg->exit_code |= 0x80;
	}
}

int			main(int argc, char **argv)
{
	t_st_config	cfg = {0};
	char		**args = NULL;

	g_cfg = &cfg;
	program_invocation_name = program_invocation_short_name;
	args = parse_options(&cfg, argc, argv);
	if (!*args && !cfg.process_table_size)
		errx(EXIT_FAILURE, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);
	if (cfg.process_table_size)
		attach_running_processes(&cfg);
	if (*args)
		spawn_child_process(&cfg, args);
	if (!cfg.running_processes)
		return (EXIT_FAILURE);
	set_signals(&cfg.blocked);
	if (cfg.summary)
		init_summary(&cfg);
	wait_processes(&cfg);
	terminate();
	return (cfg.exit_code);
}
