#pragma once

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

/*
** ft_strace global configuration
*/
typedef struct	s_st_config
{
	int			summary;			// -c and -C print summary
	int			hide_output;		// -c hides regular output
	pid_t		*pid_table;			// pids of processes to attach (-p)
	size_t		pid_table_size;		// count of processes to attach (-p)
	size_t		process_count;		// count of processes currently attached
}				t_st_config;

/*
** functions
*/
size_t			parse_pid_list(pid_t **dest, char *pid_argument);
char			**parse_options(t_st_config *cfg,  int argc, char **argv);
char			*find_command(char *cmd_name);
pid_t			execute_command(char *command, char **argv);
int				trace_process(pid_t pid);
void			process_event_loop(t_st_config *cfg);
