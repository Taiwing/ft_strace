#include "ft_strace.h"
#include <string.h>

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

static void	print_return_value(uint32_t value, enum e_syscall_type type)
{
	const char	*errname, *errdesc;
	int32_t		svalue = (int32_t)value;

	stprintf(NULL, ") = ");
	if (type != TLINT || svalue >= 0)
	{
		print_parameter(0, type, value, 0);
		stprintf(NULL, "\n");
		return ;
	}
	svalue = -svalue;
	switch (svalue)
	{
		case ERESTARTSYS:
		case ERESTARTNOINTR:
		case ERESTARTNOHAND:
		case ERESTART_RESTARTBLOCK:
			type = TNONE;
			errname = g_erestart_name[svalue];
			errdesc = g_erestart_desc[svalue];
			break ;
		default:
			errname = strerrorname_np(svalue);
			errdesc = strerror(svalue);
			svalue = -1;
			break ;
	}
	print_parameter(0, type, svalue, 0);
	stprintf(NULL, " %s (%s)\n", errname, errdesc);
}

static void	print_syscall_exit_32(t_user_regs_32 *regs,
	const t_syscall *syscall)
{
	int					i;
	uint32_t			size;
	enum e_syscall_type	type;

	if (!syscall)
	{
		stprintf(NULL, ") = %ld\n", regs->eax);
		return ;
	}
	for (i = 0; i < SYSCALL_MAX_PARAMETERS
		&& !(IS_WAIT_TYPE(syscall->parameter_type[i])
			|| syscall->parameter_type[i] == TNONE); ++i);
	for (; i < SYSCALL_MAX_PARAMETERS
		&& syscall->parameter_type[i] != TNONE; ++i)
	{
		size = 0;
		type = syscall->parameter_type[i];
		if (type == TSCHAR)
			size = REGS_32_ARRAY(regs, (i + 1));
		else if (type == TWSCHAR)
			size = (int32_t)regs->eax < 0 ? 0 : regs->eax;
		else if (type == TWSTR && regs->eax != 0)
			size = regs->eax;
		else if (type == TWSTR)
			type = TPTR;
		print_parameter(!!i, type, REGS_32_ARRAY(regs, i), size);
	}
	print_return_value(regs->eax, syscall->return_type);
}

static void	print_syscall_entry_32(t_st_config *cfg, t_st_process *process,
	t_user_regs_32 *regs, const t_syscall *syscall)
{
	uint32_t	size;

	if (!syscall)
	{
		print_regset_32(cfg, regs); //DEBUG
		stprintf(cfg, "unknown_syscall_%#lx(", process->current_syscall);
		return ;
	}
	stprintf(cfg, "%s(", syscall->name);
	for (int i = 0; i < SYSCALL_MAX_PARAMETERS
		&& !IS_WAIT_TYPE(syscall->parameter_type[i])
		&& syscall->parameter_type[i] != TNONE; ++i)
	{
		size = syscall->parameter_type[i] == TSCHAR ?
			REGS_32_ARRAY(regs, (i + 1)) : 0;
		print_parameter(!!i, syscall->parameter_type[i],
			REGS_32_ARRAY(regs, i), size);
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
	if (!process->in_syscall)
		print_syscall_entry_32(cfg, process, regs, syscall);
	else if (process->interrupted_syscall && syscall)
		stprintf(cfg, "<... %s resumed>", syscall->name);
	else if (process->interrupted_syscall)
		stprintf(cfg, "<... unknown_syscall_%lx resumed>",
			process->current_syscall);
	if (process->in_syscall)
		print_syscall_exit_32(regs, syscall);
}
