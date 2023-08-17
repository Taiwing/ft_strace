#include "ft_strace.h"

static void	print_regset_32(t_st_config *cfg, t_user_regs_32 *regs)
{
	stprintf(cfg, "{");
	stprintf(NULL, " ebx = %#x,", regs->ebx);
	stprintf(NULL, " ecx = %#x,", regs->ecx);
	stprintf(NULL, " edx = %#x,", regs->edx);
	stprintf(NULL, " esi = %#x,", regs->esi);
	stprintf(NULL, " edi = %#x,", regs->edi);
	stprintf(NULL, " ebp = %#x,", regs->ebp);
	stprintf(NULL, " eax = %#x,", regs->eax);
	stprintf(NULL, " xds = %#x,", regs->xds);
	stprintf(NULL, " xes = %#x,", regs->xes);
	stprintf(NULL, " xfs = %#x,", regs->xfs);
	stprintf(NULL, " xgs = %#x,", regs->xgs);
	stprintf(NULL, " orig_eax = %#x,", regs->orig_eax);
	stprintf(NULL, " eip = %#x,", regs->eip);
	stprintf(NULL, " xcs = %#x,", regs->xcs);
	stprintf(NULL, " eflags = %#x,", regs->eflags);
	stprintf(NULL, " esp = %#x,", regs->esp);
	stprintf(NULL, " xss = %#x ", regs->xss);
	stprintf(NULL, "}\n");
}

static void	print_syscall_exit_32(t_user_regs_32 *regs,
	const t_syscall *syscall)
{
	int	i;

	if (!syscall)
	{
		stprintf(NULL, ") = %d\n", regs->eax);
		return ;
	}
	for (i = 0; i < SYSCALL_MAX_PARAMETERS
		&& !(IS_WAIT_TYPE(syscall->parameter_type[i])
			|| syscall->parameter_type[i] == TNONE); ++i);
	for (; i < SYSCALL_MAX_PARAMETERS
		&& syscall->parameter_type[i] != TNONE; ++i)
	{
		if (i != 0)
			stprintf(NULL, ", ");
		stprintf(NULL, "%#x", REGS_32_ARRAY(regs, i));
	}
	stprintf(NULL, ") = %d\n", regs->eax);
}

static void	print_syscall_entry_32(t_st_config *cfg, t_st_process *process,
	t_user_regs_32 *regs, const t_syscall *syscall)
{
	if (!syscall)
	{
		print_regset_32(cfg, regs); //DEBUG
		stprintf(cfg, "unknown_syscall_%#x(", process->current_syscall);
		return ;
	}
	stprintf(cfg, "%s(", syscall->name);
	for (int i = 0; i < SYSCALL_MAX_PARAMETERS
		&& !IS_WAIT_TYPE(syscall->parameter_type[i])
		&& syscall->parameter_type[i] != TNONE; ++i)
	{
		if (i != 0)
			stprintf(NULL, ", ");
		stprintf(NULL, "%#x", REGS_32_ARRAY(regs, i));
	}
}

void	print_syscall_32(t_st_config *cfg)
{
	t_st_process				*process = cfg->current_process;
	t_user_regs_32				*regs = &process->regs.regs32;
	const t_syscall				*syscall = NULL;

	if (process->current_syscall >= 0
		&& process->current_syscall < G_SYSCALL_X86_I386
		&& !!g_syscall_x86_i386[process->current_syscall].name)
		syscall = &g_syscall_x86_i386[process->current_syscall];
	if (!process->in_syscall || process->interrupted_syscall)
		print_syscall_entry_32(cfg, process, regs, syscall);
	if (process->in_syscall)
		print_syscall_exit_32(regs, syscall);
}
