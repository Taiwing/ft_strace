#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

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

static void	print_syscall_32(t_st_config *cfg, t_user_regs_32 *regs)
{
	int		nargs;

	if (regs->orig_eax > SYSCALL_32_MAX
		|| g_syscall_32[regs->orig_eax].name == NULL)
	{
		print_regset_32(cfg, regs); //DEBUG
		stprintf(NULL, "unknown_syscall_%#x(", regs->orig_eax);
	}
	else
		stprintf(cfg, "%s(", g_syscall_32[regs->orig_eax].name);
	nargs = regs->orig_eax > SYSCALL_32_MAX ? SYSCALL_ARG_MAX
		: g_syscall_32[regs->orig_eax].nargs;
	if (nargs > 0)
		stprintf(NULL, "%#x", regs->ebx);
	if (nargs > 1)
		stprintf(NULL, ", %#x", regs->ecx);
	if (nargs > 2)
		stprintf(NULL, ", %#x", regs->edx);
	if (nargs > 3)
		stprintf(NULL, ", %#x", regs->esi);
	if (nargs > 4)
		stprintf(NULL, ", %#x", regs->edi);
	if (nargs > 5)
		stprintf(NULL, ", %#x", regs->ebp);
	stprintf(NULL, ") = %d\n", regs->eax);
}

static void	print_syscall_64(t_st_config *cfg, t_user_regs_64 *regs)
{
	int		nargs;

	if (regs->orig_rax > SYSCALL_64_MAX
		|| g_syscall_64[regs->orig_rax].name == NULL)
	{
		print_regset_64(cfg, regs); //DEBUG
		stprintf(cfg, "unknown_syscall_%#lx(", regs->orig_rax);
	}
	else
		stprintf(cfg, "%s(", g_syscall_64[regs->orig_rax].name);
	nargs = regs->orig_rax > SYSCALL_64_MAX ? SYSCALL_ARG_MAX
		: g_syscall_64[regs->orig_rax].nargs;
	if (nargs > 0)
		stprintf(NULL, "%#lx", regs->rdi);
	if (nargs > 1)
		stprintf(NULL, ", %#lx", regs->rsi);
	if (nargs > 2)
		stprintf(NULL, ", %#lx", regs->rdx);
	if (nargs > 3)
		stprintf(NULL, ", %#lx", regs->rcx);
	if (nargs > 4)
		stprintf(NULL, ", %#lx", regs->r8);
	if (nargs > 5)
		stprintf(NULL, ", %#lx", regs->r9);
	stprintf(NULL, ") = %ld\n", regs->rax);
}

void	get_syscall(t_st_config *cfg)
{
	t_user_regs		regs;
	struct iovec	io = { .iov_base = &regs, .iov_len = sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, cfg->current_process, NT_PRSTATUS, &io) < 0)
		err(EXIT_FAILURE, "ptrace");
	if (io.iov_len == sizeof(t_user_regs_32))
		print_syscall_32(cfg, &regs.regs32);
	else if (io.iov_len == sizeof(t_user_regs_64))
		print_syscall_64(cfg, &regs.regs64);
	else
		errx(EXIT_FAILURE, "Unknown architecture");
}
