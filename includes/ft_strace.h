#pragma once

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define MAX_PROCESS 1024

/*
** ft_strace global configuration
*/
typedef struct	s_st_config
{
	int			summary;						// -c and -C print summary
	int			hide_output;					// -c hides regular output
	pid_t		process_table[MAX_PROCESS];		// traced processes table
	size_t		process_table_size;				// traced processes count
	size_t		process_count;					// currently attached processes
	pid_t		current_process;				// current event's process
}				t_st_config;

/*
** functions
*/
size_t			parse_pid_list(pid_t *dest, char *pid_argument);
char			**parse_options(t_st_config *cfg,  int argc, char **argv);
char			*find_command(char *cmd_name);
pid_t			execute_command(char *command, char **argv);
int				trace_process(pid_t pid);
void			process_event_loop(t_st_config *cfg);
char			*signame(int sig);
int				stprintf(t_st_config *cfg, const char *format, ...);
void			getregset(t_st_config *cfg);
