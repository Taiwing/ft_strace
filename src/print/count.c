#include "ft_strace.h"
#include <time.h>

static t_st_summary		*get_summary(t_st_config *cfg, t_st_process *process)
{
	enum e_arch		arch;
	int				syscall;

	if (process->arch_changed)
	{
		arch = process->arch == E_ARCH_32 ? E_ARCH_64 : E_ARCH_32;
		syscall = process->last_syscall;
	}
	else
	{
		arch = process->arch;
		syscall = process->current_syscall;
	}
	if (syscall < 0 || (arch == E_ARCH_32 && syscall >= G_SYSCALL_X86_I386)
		|| (arch == E_ARCH_64 && syscall >= G_SYSCALL_X86_64))
		return (NULL);
	return (arch == E_ARCH_32 ? &cfg->summary_32[syscall]
		: &cfg->summary_64[syscall]);
}

static struct timespec	*gettime(struct timespec *time)
{
	if (clock_gettime(CLOCK_REALTIME, time) < 0)
		err(EXIT_FAILURE, "clock_gettime");
	return (time);
}

void	count_syscall_exit(t_st_config *cfg, t_st_process *process)
{
	struct timespec	end;
	t_st_summary	*summary;
	uint64_t		return_value;

	if (!(summary = get_summary(cfg, process)))
		return ;
	return_value = process->arch == E_ARCH_32 ? process->regs.regs32.eax
		: process->regs.regs64.rax;
	++summary->calls;
	summary->errors += syscall_error_return(return_value, process->arch);
	if (cfg->kernel_time)
		timeval_to_timespec(&end, &cfg->rusage.ru_stime);
	else
		gettime(&end);
	ts_sub(&end, &summary->start);
	if (ts_cmp(&end, &g_ts_zero) >= 0)
		ts_add(&summary->total, &end);
}

void	count_syscall_entry(t_st_config *cfg, t_st_process *process)
{
	struct timespec	start;
	t_st_summary	*summary;

	if (!(summary = get_summary(cfg, process)))
		return ;
	if (cfg->kernel_time)
		timeval_to_timespec(&start, &cfg->rusage.ru_stime);
	else
		gettime(&start);
	if (ts_cmp(&start, &g_ts_zero) >= 0)
		summary->start = start;
}

void	init_summary_count(t_st_config *cfg)
{
	for (int i = 0; i < G_SYSCALL_X86_I386; ++i)
		cfg->summary_32[i].syscall = i;
	for (int i = 0; i < G_SYSCALL_X86_64; ++i)
		cfg->summary_64[i].syscall = i;
}
