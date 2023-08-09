#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

static void	print_syscall_32(t_st_config *cfg, t_user_regs_32 *regs)
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

static void	print_syscall_64(t_st_config *cfg, t_user_regs_64 *regs)
{
	stprintf(cfg, "{");
	stprintf(NULL, " r15 = %#llx,", regs->r15);
	stprintf(NULL, " r14 = %#llx,", regs->r14);
	stprintf(NULL, " r13 = %#llx,", regs->r13);
	stprintf(NULL, " r12 = %#llx,", regs->r12);
	stprintf(NULL, " rbp = %#llx,", regs->rbp);
	stprintf(NULL, " rbx = %#llx,", regs->rbx);
	stprintf(NULL, " r11 = %#llx,", regs->r11);
	stprintf(NULL, " r10 = %#llx,", regs->r10);
	stprintf(NULL, " r9 = %#llx,", regs->r9);
	stprintf(NULL, " r8 = %#llx,", regs->r8);
	stprintf(NULL, " rax = %#llx,", regs->rax);
	stprintf(NULL, " rcx = %#llx,", regs->rcx);
	stprintf(NULL, " rdx = %#llx,", regs->rdx);
	stprintf(NULL, " rsi = %#llx,", regs->rsi);
	stprintf(NULL, " rdi = %#llx,", regs->rdi);
	stprintf(NULL, " orig_rax = %#llx,", regs->orig_rax);
	stprintf(NULL, " rip = %#llx,", regs->rip);
	stprintf(NULL, " cs = %#llx,", regs->cs);
	stprintf(NULL, " eflags = %#llx,", regs->eflags);
	stprintf(NULL, " rsp = %#llx,", regs->rsp);
	stprintf(NULL, " ss = %#llx ", regs->ss);
	stprintf(NULL, " fs_base = %#llx,", regs->fs_base);
	stprintf(NULL, " gs_base = %#llx,", regs->gs_base);
	stprintf(NULL, " ds = %#llx,", regs->ds);
	stprintf(NULL, " es = %#llx,", regs->es);
	stprintf(NULL, " fs = %#llx,", regs->fs);
	stprintf(NULL, " gs = %#llx ", regs->gs);
	stprintf(NULL, "}\n");
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
