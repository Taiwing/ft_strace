#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

static void	print_syscall_32(t_st_config *cfg, t_user_regs_32 *regs)
{
	if (regs->orig_eax > SYSCALL_32_MAX
		|| g_syscall_32[regs->orig_eax].name == NULL)
		stprintf(cfg, "unknown_syscall_%d(", regs->orig_eax);
	else
		stprintf(cfg, "%s(", g_syscall_32[regs->orig_eax].name);
	if (g_syscall_32[regs->orig_eax].nargs > 0)
		stprintf(NULL, "%#x", regs->ebx);
	if (g_syscall_32[regs->orig_eax].nargs > 1)
		stprintf(NULL, ", %#x", regs->ecx);
	if (g_syscall_32[regs->orig_eax].nargs > 2)
		stprintf(NULL, ", %#x", regs->edx);
	if (g_syscall_32[regs->orig_eax].nargs > 3)
		stprintf(NULL, ", %#x", regs->esi);
	if (g_syscall_32[regs->orig_eax].nargs > 4)
		stprintf(NULL, ", %#x", regs->edi);
	if (g_syscall_32[regs->orig_eax].nargs > 5)
		stprintf(NULL, ", %#x", regs->ebp);
	stprintf(NULL, ") = %#x\n", regs->eax);
}

static void	print_syscall_64(t_st_config *cfg, t_user_regs_64 *regs)
{
	if (regs->orig_rax > SYSCALL_64_MAX
		|| g_syscall_64[regs->orig_rax].name == NULL)
		stprintf(cfg, "unknown_syscall_%d(", regs->orig_rax);
	else
		stprintf(cfg, "%s(", g_syscall_64[regs->orig_rax].name);
	if (g_syscall_64[regs->orig_rax].nargs > 0)
		stprintf(NULL, "%#x", regs->rdi);
	if (g_syscall_64[regs->orig_rax].nargs > 1)
		stprintf(NULL, ", %#x", regs->rsi);
	if (g_syscall_64[regs->orig_rax].nargs > 2)
		stprintf(NULL, ", %#x", regs->rdx);
	if (g_syscall_64[regs->orig_rax].nargs > 3)
		stprintf(NULL, ", %#x", regs->rcx);
	if (g_syscall_64[regs->orig_rax].nargs > 4)
		stprintf(NULL, ", %#x", regs->r8);
	if (g_syscall_64[regs->orig_rax].nargs > 5)
		stprintf(NULL, ", %#x", regs->r9);
	stprintf(NULL, ") = %#x\n", regs->rax);
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
