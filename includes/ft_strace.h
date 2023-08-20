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
#include <sys/resource.h>

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
typedef struct		s_st_process
{
	pid_t			pid;					// process id
	enum e_arch		arch;					// process architecture
	t_user_regs		regs;					// process registers
	sig_atomic_t	running;				// process is running
	int				in_syscall;				// process is in syscall
	int				current_syscall;		// current syscall number
	int				interrupted;			// syscall was interrupted
	int				last_syscall;			// last syscall number
	int				arch_changed;			// architecture changed
}					t_st_process;

/*
** ft_strace summary structure
*/
typedef struct		s_st_summary
{
	int				syscall;				// syscall number
	uint64_t		calls;					// syscall count
	uint64_t		errors;					// error count
	struct timespec start;					// kernel start time
	struct timespec total;					// kernel total time
	double			time;					// total syscall time (s)
	uint64_t		avgtime;				// average syscall time (us)
}					t_st_summary;

/*
** ft_strace global configuration
*/
typedef struct		s_st_config
{
	int				summary;						// -c and -C print summary
	int				hide_output;					// -c hides regular output
	sigset_t		blocked;						// signals to block
	t_st_process	process_table[MAX_PROCESS];		// traced processes table
	size_t			process_table_size;				// traced processes count
	sig_atomic_t	running_processes;				// running processes count
	t_st_process	*current_process;				// current event's process
	t_st_process	*child_process;					// syscall process
	int				arch_changed;					// architecture changed
	t_st_summary	summary_32[G_SYSCALL_X86_I386];	// 32 bit summary data
	t_st_summary	summary_64[G_SYSCALL_X86_64];	// 64 bit summary data
	struct rusage	rusage;							// resource usage
	int				exit_code;						// exit code
}					t_st_config;

// global configuration
extern t_st_config	*g_cfg;

/*
** error codes that should be defined in errno.h
*/
#ifndef MAX_ERRNO
# define MAX_ERRNO 4095
#endif
#ifndef ERESTARTSYS
# define ERESTARTSYS 512
#endif
#ifndef ERESTARTNOINTR
# define ERESTARTNOINTR 513
#endif
#ifndef ERESTARTNOHAND
# define ERESTARTNOHAND 514
#endif
#ifndef ERESTART_RESTARTBLOCK
# define ERESTART_RESTARTBLOCK 516
#endif

/*
** Their names and descriptions
*/
extern const char	*g_erestart_name[];
extern const char	*g_erestart_desc[];

/*
** Time
*/
#define NSEC_PER_SEC	1000000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_USEC	1000L
extern const struct timespec	g_ts_zero;

/*
** functions
*/
size_t			parse_pid_list(t_st_process *dest, char *pid_argument);
char			**parse_options(t_st_config *cfg,  int argc, char **argv);
void			terminate(void);
void			set_signals(sigset_t *blocked);
void			unblock_signals(void);
void			block_signals(sigset_t *blocked);
pid_t			st_wait(t_st_config *cfg, pid_t pid, int *status, int options);
char			*find_command(char *cmd_name);
pid_t			execute_command(t_st_config *cfg, char *command, char **argv);
int				trace_process(t_st_config *cfg, pid_t pid);
t_st_process	*find_process(t_st_config *cfg, pid_t pid);
void			wait_processes(t_st_config *cfg);
char			*signame(int sig);
int				stprintf(t_st_config *cfg, const char *format, ...);
void			get_process_syscall(t_st_process *process);
void			update_process_syscall(t_st_process *process);
void			print_syscall(t_st_config *cfg);
void			print_syscall_32(t_st_config *cfg);
void			print_syscall_64(t_st_config *cfg);
void			print_signal(t_st_config *cfg,
					unsigned int sig, unsigned int stopped, siginfo_t *si);
void			print_parameter(int comma, enum e_syscall_type type,
					uint64_t param, uint64_t size, enum e_arch arch);
void			print_restart_syscall(int syscall, enum e_arch arch);
int				syscall_error_return(uint64_t value, enum e_arch arch);
void			init_summary_count(t_st_config *cfg);
void			count_syscall_entry(t_st_config *cfg, t_st_process *process);
void			count_syscall_exit(t_st_config *cfg, t_st_process *process);
void			print_summary(t_st_config *cfg);
void			print_return_value(uint64_t value, enum e_syscall_type type,
					enum e_arch arch);
void			ts_add(struct timespec *dest, const struct timespec *src);
void			ts_sub(struct timespec *dest, const struct timespec *src);
int				ts_cmp(const struct timespec *a, const struct timespec *b);
double			ts_to_second(const struct timespec *ts);
double			ts_to_usec(const struct timespec *ts);
void			timeval_to_timespec(struct timespec *dest,
					const struct timeval *src);
