#include "ft_strace.h"
#include <string.h>

static void	print_regset_64(t_st_config *cfg, t_user_regs_64 *regs)
{
	stprintf(cfg, "{");
	stprintf(NULL, " r15 = %#lx,", regs->r15);
	stprintf(NULL, " r14 = %#lx,", regs->r14);
	stprintf(NULL, " r13 = %#lx,", regs->r13);
	stprintf(NULL, " r12 = %#lx,", regs->r12);
	stprintf(NULL, " rbp = %#lx,", regs->rbp);
	stprintf(NULL, " rbx = %#lx,", regs->rbx);
	stprintf(NULL, " r11 = %#lx,", regs->r11);
	stprintf(NULL, " r10 = %#lx,", regs->r10);
	stprintf(NULL, " r9 = %#lx,", regs->r9);
	stprintf(NULL, " r8 = %#lx,", regs->r8);
	stprintf(NULL, " rax = %#lx,", regs->rax);
	stprintf(NULL, " rcx = %#lx,", regs->rcx);
	stprintf(NULL, " rdx = %#lx,", regs->rdx);
	stprintf(NULL, " rsi = %#lx,", regs->rsi);
	stprintf(NULL, " rdi = %#lx,", regs->rdi);
	stprintf(NULL, " orig_rax = %#lx,", regs->orig_rax);
	stprintf(NULL, " rip = %#lx,", regs->rip);
	stprintf(NULL, " cs = %#lx,", regs->cs);
	stprintf(NULL, " eflags = %#lx,", regs->eflags);
	stprintf(NULL, " rsp = %#lx,", regs->rsp);
	stprintf(NULL, " ss = %#lx ", regs->ss);
	stprintf(NULL, " fs_base = %#lx,", regs->fs_base);
	stprintf(NULL, " gs_base = %#lx,", regs->gs_base);
	stprintf(NULL, " ds = %#lx,", regs->ds);
	stprintf(NULL, " es = %#lx,", regs->es);
	stprintf(NULL, " fs = %#lx,", regs->fs);
	stprintf(NULL, " gs = %#lx ", regs->gs);
	stprintf(NULL, "}\n");
}

static void	print_return_value_64(uint64_t value, enum e_syscall_type type)
{
	const char	*errname, *errdesc;
	int64_t		svalue = (int64_t)value;

	stprintf(NULL, ") = ");
	if (type == TNONE || value < (uint64_t)-MAX_ERRNO)
	{
		print_parameter(0, type, value, 0, E_ARCH_64);
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
			errname = g_erestart_name[svalue];
			errdesc = g_erestart_desc[svalue];
			type = TNONE;
			break ;
		default:
			errname = strerrorname_np(svalue);
			errdesc = strerror(svalue);
			type = TLINT;
			svalue = -1;
			break ;
	}
	print_parameter(0, type, svalue, 0, E_ARCH_64);
	stprintf(NULL, " %s (%s)\n", errname, errdesc);
}

static void	print_syscall_exit_64(t_user_regs_64 *regs,
	const t_syscall *syscall)
{
	int					i;
	uint64_t			size;
	enum e_syscall_type	type;

	if (!syscall)
	{
		stprintf(NULL, ") = %ld\n", regs->rax);
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
			size = REGS_64_ARRAY(regs, (i + 1));
		else if (type == TWSCHAR)
			size = (int64_t)regs->rax < 0 ? 0 : regs->rax;
		else if (type == TWSTR && regs->rax != 0)
			size = regs->rax;
		else if (type == TWSTR)
			type = TPTR;
		print_parameter(!!i, type, REGS_64_ARRAY(regs, i), size, E_ARCH_64);
	}
	print_return_value_64(regs->rax, syscall->return_type);
}

static void	print_syscall_entry_64(t_st_config *cfg, t_st_process *process,
	t_user_regs_64 *regs, const t_syscall *syscall)
{
	uint64_t	size;

	if (!syscall)
	{
		print_regset_64(cfg, regs); //DEBUG
		stprintf(cfg, "unknown_syscall_%#lx(", process->current_syscall);
		return ;
	}
	stprintf(cfg, "%s(", syscall->name);
	for (int i = 0; i < SYSCALL_MAX_PARAMETERS
		&& !IS_WAIT_TYPE(syscall->parameter_type[i])
		&& syscall->parameter_type[i] != TNONE; ++i)
	{
		size = syscall->parameter_type[i] == TSCHAR ?
			REGS_64_ARRAY(regs, (i + 1)) : 0;
		print_parameter(!!i, syscall->parameter_type[i],
			REGS_64_ARRAY(regs, i), size, E_ARCH_64);
	}
}

void	print_syscall_64(t_st_config *cfg)
{
	t_st_process				*process = cfg->current_process;
	t_user_regs_64				*regs = &process->regs.regs64;
	const t_syscall				*syscall = NULL;

	if (process->current_syscall >= 0
		&& process->current_syscall < G_SYSCALL_X86_64
		&& !!g_syscall_x86_64[process->current_syscall].name)
		syscall = &g_syscall_x86_64[process->current_syscall];
	if (!process->in_syscall)
	{
		print_syscall_entry_64(cfg, process, regs, syscall);
		if (process->current_syscall == 219)
			print_restart_syscall(process->last_syscall, E_ARCH_64);
	}
	else if (process->interrupted && syscall)
		stprintf(cfg, "<... %s resumed>", syscall->name);
	else if (process->interrupted)
		stprintf(cfg, "<... unknown_syscall_%lx resumed>",
			process->current_syscall);
	if (process->in_syscall)
		print_syscall_exit_64(regs, syscall);
}
