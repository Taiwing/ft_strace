#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

static void	print_syscall_32(t_st_config *cfg, t_user_regs_32 *regs)
{
	int		nargs;

	if (regs->orig_eax > SYSCALL_32_MAX
		|| g_syscall_32[regs->orig_eax].name == NULL)
		stprintf(cfg, "unknown_syscall_%#x(", regs->orig_eax);
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
		stprintf(cfg, "unknown_syscall_%#x(", regs->orig_rax);
	else
		stprintf(cfg, "%s(", g_syscall_64[regs->orig_rax].name);
	nargs = regs->orig_rax > SYSCALL_64_MAX ? SYSCALL_ARG_MAX
		: g_syscall_64[regs->orig_rax].nargs;
	if (nargs > 0)
		stprintf(NULL, "%#x", regs->rdi);
	if (nargs > 1)
		stprintf(NULL, ", %#x", regs->rsi);
	if (nargs > 2)
		stprintf(NULL, ", %#x", regs->rdx);
	if (nargs > 3)
		stprintf(NULL, ", %#x", regs->rcx);
	if (nargs > 4)
		stprintf(NULL, ", %#x", regs->r8);
	if (nargs > 5)
		stprintf(NULL, ", %#x", regs->r9);
	stprintf(NULL, ") = %d\n", regs->rax);
}

void	getregset(t_st_config *cfg)
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
