#include "ft_strace.h"
#include "syscall.h"
#include <sys/uio.h>
#include <elf.h>

void	update_process_syscall(t_st_process *process)
{
	process->in_syscall = !process->in_syscall;
	process->interrupted = 0;
	if (process->arch_changed && !process->in_syscall)
	{
		stprintf(g_cfg, "[ Process PID=%5u runs in %d bit mode. ]\n",
			process->pid, process->arch == E_ARCH_32 ? 32 : 64);
		process->arch_changed = 0;
	}
}

void	get_process_syscall(t_st_process *process)
{
	enum e_arch		arch;
	struct iovec	io = {
		.iov_base = &process->regs,
		.iov_len = sizeof(process->regs),
	};

	if (ptrace(PTRACE_GETREGSET, process->pid, NT_PRSTATUS, &io) < 0)
		err(EXIT_FAILURE, "ptrace");
	arch = GET_ARCH(io.iov_len);
	if (arch != process->arch && process->arch != E_ARCH_UNKNOWN)
		process->arch_changed = 1;
	process->arch = arch;
	if (process->arch == E_ARCH_UNKNOWN)
		errx(EXIT_FAILURE, "Unknown architecture");
	if (!process->in_syscall || process->arch_changed)
	{
		process->last_syscall = process->current_syscall;
		process->current_syscall = process->arch == E_ARCH_32
			? process->regs.regs32.orig_eax : process->regs.regs64.orig_rax;
	}
}
