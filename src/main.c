#include "ft_strace.h"

int	main(int argc, char **argv)
{
	t_st_config	cfg = { 0 };
	char		**args = parse_arguments(&cfg, argc, argv);

	if (!*args && !cfg.pid_list)
		error(EXIT_FAILURE, 0, "must have 'command [args]' or '-p pid'\n"
			"Try '%s -h' for more information.", program_invocation_name);
	//TODO: parse pid_list with strtok(pid_list, ", ") (or strsep() more likely)
	if (*args)
	{
		printf("%s", *args++);
		while (*args)
			printf(" %s", *args++);
		putchar('\n');
	}
	return (EXIT_SUCCESS);
}
