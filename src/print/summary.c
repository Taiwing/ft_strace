#include "ft_strace.h"

static t_st_summary	*get_summary(t_st_config *cfg, t_st_process *process)
{
	enum e_arch		arch;
	int				syscall;

	if (!process->in_syscall)
		return (NULL);
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

void			count_syscall(t_st_config *cfg, t_st_process *process)
{
	t_st_summary	*summary;
	uint64_t		return_value;

	if (!(summary = get_summary(cfg, process)))
		return ;
	return_value = process->arch == E_ARCH_32 ? process->regs.regs32.eax
		: process->regs.regs64.rax;
	++summary->calls;
	summary->errors += syscall_error_return(return_value, process->arch);
}
