#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

static void	print_syscall_32(t_st_config *cfg, t_user_regs_32 *regs)
{
	stprintf(cfg, "{");
	stprintf(cfg, " ebx = %#x,", regs->ebx);
	stprintf(cfg, " ecx = %#x,", regs->ecx);
	stprintf(cfg, " edx = %#x,", regs->edx);
	stprintf(cfg, " esi = %#x,", regs->esi);
	stprintf(cfg, " edi = %#x,", regs->edi);
	stprintf(cfg, " ebp = %#x,", regs->ebp);
	stprintf(cfg, " eax = %#x,", regs->eax);
	stprintf(cfg, " xds = %#x,", regs->xds);
	stprintf(cfg, " xes = %#x,", regs->xes);
	stprintf(cfg, " xfs = %#x,", regs->xfs);
	stprintf(cfg, " xgs = %#x,", regs->xgs);
	stprintf(cfg, " orig_eax = %#x,", regs->orig_eax);
	stprintf(cfg, " eip = %#x,", regs->eip);
	stprintf(cfg, " xcs = %#x,", regs->xcs);
	stprintf(cfg, " eflags = %#x,", regs->eflags);
	stprintf(cfg, " esp = %#x,", regs->esp);
	stprintf(cfg, " xss = %#x ", regs->xss);
	stprintf(cfg, "}\n");
}

static void	print_syscall_64(t_st_config *cfg, t_user_regs_64 *regs)
{
	stprintf(cfg, "{");
	stprintf(cfg, " r15 = %#llx,", regs->r15);
	stprintf(cfg, " r14 = %#llx,", regs->r14);
	stprintf(cfg, " r13 = %#llx,", regs->r13);
	stprintf(cfg, " r12 = %#llx,", regs->r12);
	stprintf(cfg, " rbp = %#llx,", regs->rbp);
	stprintf(cfg, " rbx = %#llx,", regs->rbx);
	stprintf(cfg, " r11 = %#llx,", regs->r11);
	stprintf(cfg, " r10 = %#llx,", regs->r10);
	stprintf(cfg, " r9 = %#llx,", regs->r9);
	stprintf(cfg, " r8 = %#llx,", regs->r8);
	stprintf(cfg, " rax = %#llx,", regs->rax);
	stprintf(cfg, " rcx = %#llx,", regs->rcx);
	stprintf(cfg, " rdx = %#llx,", regs->rdx);
	stprintf(cfg, " rsi = %#llx,", regs->rsi);
	stprintf(cfg, " rdi = %#llx,", regs->rdi);
	stprintf(cfg, " orig_rax = %#llx,", regs->orig_rax);
	stprintf(cfg, " rip = %#llx,", regs->rip);
	stprintf(cfg, " cs = %#llx,", regs->cs);
	stprintf(cfg, " eflags = %#llx,", regs->eflags);
	stprintf(cfg, " rsp = %#llx,", regs->rsp);
	stprintf(cfg, " ss = %#llx ", regs->ss);
	stprintf(cfg, " fs_base = %#llx,", regs->fs_base);
	stprintf(cfg, " gs_base = %#llx,", regs->gs_base);
	stprintf(cfg, " ds = %#llx,", regs->ds);
	stprintf(cfg, " es = %#llx,", regs->es);
	stprintf(cfg, " fs = %#llx,", regs->fs);
	stprintf(cfg, " gs = %#llx ", regs->gs);
	stprintf(cfg, "}\n");
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
