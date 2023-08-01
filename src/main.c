#include "ft_strace.h"

int	main(int argc, char **argv)
{
	if (argc < 2)
		error(EXIT_FAILURE, 0, "must have PROG [ARGS] or -p PID\n"
			"Try '%s -h' for more information.", program_invocation_name);
	printf("%s", *++argv);
	while (*++argv)
		printf(" %s", *argv);
	putchar('\n');
	return (EXIT_SUCCESS);
}
