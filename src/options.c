#include "ft_strace.h"
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>

// ft_strace short options
#define FT_ST_OPTS	"+cChp:"

const struct option		g_st_options[] = {
	{	"summary-only",		no_argument,		NULL,	'c'	},
	{	"summary",			no_argument,		NULL,	'C'	},
	{	"help",				no_argument,		NULL,	'h'	},
	{	"attach",			required_argument,	NULL,	'p'	},
	{	NULL,				0,					NULL,	0	},
};

const char				*g_st_arg_names[] = { NULL, NULL, NULL, "pid", NULL };

const char				*g_st_help[] = {
	"Report only a summary of time, call and error counts per syscall.",
	"Like -c but also print regular output while processes are running.",
	"Print this.",
	"Attach to the process with the process ID 'pid' and begin tracing.",
	NULL,
};

const char				*g_st_usage[] = {
	"[-cCh] command [args]",
	"[-cCh] -p pid [ command [args] ]",
	NULL,
};

static void	usage(int status)
{
	const struct option		*options = g_st_options;
	const char				**help = g_st_help;
	const char				**usage = g_st_usage;
	const char				**arg_names = g_st_arg_names;

	printf("Usage:\n");
	while (*usage)
		printf("\t%s %s\n", program_invocation_name, *usage++);
	printf("\nOptions:\n");
	while (options->name && *help)
	{
		putchar('\t');
		if (isalnum(options->val))
			printf("-%c, ", options->val);
		printf("--%s", options->name);
		if (options->has_arg == required_argument)
			printf("=%s", *arg_names);
		else if (options->has_arg == optional_argument)
			printf("[=%s]", *arg_names);
		printf("\n\t\t%s\n", *help);
		++options;
		++help;
		++arg_names;
	}
	exit(status);
}

char	**parse_options(t_st_config *cfg,  int argc, char **argv)
{
	int	c;

	while ((c = getopt_long(argc, argv, FT_ST_OPTS, g_st_options, NULL)) != -1)
		switch (c)
		{
			case 'c': cfg->hide_output = cfg->summary = 1;				break;
			case 'C': cfg->hide_output = 0; cfg->summary = 1;			break;
			case 'p':
				cfg->pid_table_size = parse_pid_list(&cfg->pid_table, optarg);
																		break;
			default: usage(c != 'h');									break;
		}
	return (argv + optind);
}
