#include "ft_strace.h"

const char	*g_erestart_name[] = {
	[ERESTARTSYS] = "ERESTARTSYS",
	[ERESTARTNOINTR] = "ERESTARTNOINTR",
	[ERESTARTNOHAND] = "ERESTARTNOHAND",
	[ERESTART_RESTARTBLOCK] = "ERESTART_RESTARTBLOCK",
};

const char	*g_erestart_desc[] = {
	[ERESTARTSYS] = "To be restarted if SA_RESTART is set",
	[ERESTARTNOINTR] = "To be restarted",
	[ERESTARTNOHAND] = "To be restarted if no handler",
	[ERESTART_RESTARTBLOCK] = "Interrupted by signal",
};

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

void	print_restart_syscall(int syscall, enum e_arch arch)
{
	const char	*name = NULL;

	if (arch == E_ARCH_32 && syscall >= 0 && syscall < G_SYSCALL_X86_I386
		&& g_syscall_x86_i386[syscall].name)
		name = g_syscall_x86_i386[syscall].name;
	else if (arch == E_ARCH_64 && syscall >= 0 && syscall < G_SYSCALL_X86_64
		&& g_syscall_x86_64[syscall].name)
		name = g_syscall_x86_64[syscall].name;
	stprintf(NULL, "<... resuming interrupted %s ...>",
		name ? name : "system call");
}

void	print_signal(t_st_config *cfg,
	unsigned int sig, unsigned int group_stop, siginfo_t *si)
{
	if (!group_stop && si)
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
}
