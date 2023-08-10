#pragma once

#define _GNU_SOURCE

#include "syscall.h"
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

// process architecture
enum e_arch { E_ARCH_UNKNOWN = 0, E_ARCH_32, E_ARCH_64 };

// get architecture from register structure size
#define GET_ARCH(size) (\
	size == sizeof(t_user_regs_64) ? E_ARCH_64 \
	: size == sizeof(t_user_regs_32) ? E_ARCH_32 \
	: E_ARCH_UNKNOWN \
)

/*
** process state
*/
typedef struct	s_st_process
{
	pid_t		pid;					// process id
	enum e_arch	arch;					// process architecture
	t_user_regs	regs;					// process registers
	int			in_syscall;				// process is in syscall
	int			interrupted_syscall;	// syscall was interrupted
}				t_st_process;

/*
** ft_strace global configuration
*/
typedef struct		s_st_config
{
	int				summary;						// -c and -C print summary
	int				hide_output;					// -c hides regular output
	t_st_process	process_table[MAX_PROCESS];		// traced processes table
	size_t			process_table_size;				// traced processes count
	size_t			running_processes;				// running processes count
	t_st_process	*current_process;				// current event's process
}					t_st_config;

/*
** functions
*/
size_t			parse_pid_list(t_st_process *dest, char *pid_argument);
char			**parse_options(t_st_config *cfg,  int argc, char **argv);
char			*find_command(char *cmd_name);
pid_t			execute_command(char *command, char **argv);
int				trace_process(pid_t pid);
t_st_process	*find_process(t_st_config *cfg, pid_t pid);
void			process_event_loop(t_st_config *cfg);
char			*signame(int sig);
int				stprintf(t_st_config *cfg, const char *format, ...);
void			get_syscall(t_st_config *cfg);
