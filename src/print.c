#include "ft_strace.h"

int		stprintf(t_st_config *cfg, const char *format, ...)
{
	va_list		args;
	int			ret;

	if (cfg && cfg->running_processes > 1)
		fprintf(stderr, "[pid %5u] ", cfg->current_process->pid);
	va_start(args, format);
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return (ret);
}

void	print_signal(t_st_config *cfg,
	unsigned int sig, unsigned int stopped, siginfo_t *si)
{
	if (!stopped && si)
	{
		if (si->si_code == SI_USER)
			stprintf(cfg, "--- %s {si_signo=%s, si_code=SI_USER, si_pid=%d,"
				" si_uid=%d} ---\n", signame(sig), signame(si->si_signo),
				si->si_pid, si->si_uid);
		else if (si->si_code == SI_KERNEL)
			stprintf(cfg, "--- %s {si_signo=%s, si_code=SI_KERNEL} ---\n",
				signame(sig), signame(si->si_signo));
		else
			stprintf(cfg, "--- %s {si_signo=%s, si_code=%d, si_pid=%d,"
				" si_uid=%d} ---\n", signame(sig), signame(si->si_signo),
				si->si_code, si->si_pid, si->si_uid);
	}
	else
		stprintf(cfg, "--- stopped by %s ---\n", signame(sig));
}

void	print_syscall(t_st_config *cfg)
{
	if (cfg->current_process->arch == E_ARCH_32)
		print_syscall_32(cfg);
	else
		print_syscall_64(cfg);
	cfg->current_process->in_syscall = !cfg->current_process->in_syscall;
	cfg->current_process->interrupted_syscall = 0;
	if (cfg->current_process->arch_changed && !cfg->current_process->in_syscall)
	{
		stprintf(cfg, "[ Process PID=%5u runs in %d bit mode. ]\n",
			cfg->current_process->pid,
			cfg->current_process->arch == E_ARCH_32 ? 32 : 64);
		cfg->current_process->arch_changed = 0;
	}
}
