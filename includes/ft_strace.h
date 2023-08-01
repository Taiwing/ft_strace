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
	int			summary;		// -c and -C print summary
	int			hide_output;	// -c hides regular output
	const char	*pid_list;		// argument for --attach option
}				t_st_config;

/*
** functions
*/
char			**parse_arguments(t_st_config *cfg,  int argc, char **argv);
