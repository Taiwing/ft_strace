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
			printf("pid_table[%zu] = %d\n", i, g_cfg.pid_table[i]);
	}
	if (*args)
	{
		char	*command = find_command(*args);

		if (!command)
			exit(EXIT_FAILURE);
		execute_command(command, args);
	}
	return (EXIT_SUCCESS);
}
