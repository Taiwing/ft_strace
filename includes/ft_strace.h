#pragma once

#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>

/*
** ft_strace global configuration
*/
typedef struct	s_st_config
{
	int			summary;			// -c and -C print summary
	int			hide_output;		// -c hides regular output
	pid_t		*pid_table;			// pids of processes to attach (-p)
	size_t		pid_table_size;		// count of processes to attach (-p)
}				t_st_config;

/*
** functions
*/
size_t			parse_pid_list(pid_t **dest, char *pid_argument);
char			**parse_options(t_st_config *cfg,  int argc, char **argv);
