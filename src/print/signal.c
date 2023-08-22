#include "ft_strace.h"

static void	print_sigchld(int si_code, siginfo_t *si)
{
	stprintf(NULL, ", si_pid=%d, si_uid=%d, si_status=",
		si->si_pid, si->si_uid);
	if (si_code == CLD_EXITED)
		stprintf(NULL, "%d", si->si_status);
	else
		stprintf(NULL, "%s", signame(si->si_status));
	stprintf(NULL, ", si_utime=%llu, si_stime=%llu} ---\n",
		si->si_utime, si->si_stime);
}

static int	print_specific_signal(unsigned int sig, siginfo_t *si)
{
	const t_si_code_names	*si_code_names;

	if (sig <= 0 || sig >= SI_CODE_NAMES_SIZE)
		return (1);
	si_code_names = g_si_code_names + sig;
	for (size_t i = 0; i < si_code_names->count; ++i)
	{
		if (si->si_code != si_code_names->si_codes[i])
			continue ;
		stprintf(NULL, "%s", si_code_names->names[i]);
		switch (sig)
		{
			case SIGILL:
			case SIGFPE:
			case SIGSEGV:
			case SIGBUS:
			case SIGTRAP:
				stprintf(NULL, ", si_addr=%p} ---\n", si->si_addr);
				break;
			case SIGCHLD:
				print_sigchld(si->si_code, si);
				break;
			default:
				stprintf(NULL, "} ---\n");
				break;
		}
		return (0);
	}
	return (1);
}

static int	print_generic_signal(siginfo_t *si)
{
	for (size_t i = 0; i < g_si_code_names[0].count; ++i)
	{
		if (si->si_code != g_si_code_names[0].si_codes[i])
			continue ;
		stprintf(NULL, "%s", g_si_code_names[0].names[i]);
		if (si->si_code == SI_USER || si->si_code == SI_TKILL)
			stprintf(NULL, ", si_pid=%d, si_uid=%d} ---\n",
				si->si_pid, si->si_uid);
		else
			stprintf(NULL, "} ---\n");
		return (0);
	}
	return (1);
}

void	print_signal(t_st_config *cfg,
	unsigned int sig, unsigned int group_stop, siginfo_t *si)
{
	if (!group_stop && si)
	{
		stprintf(cfg, "--- %s {si_signo=%s, si_code=", signame(sig),
			signame(si->si_signo));
		if (!print_specific_signal(sig, si))
			return ;
		else if (!print_generic_signal(si))
			return ;
		else
			stprintf(NULL, "%d} ---\n", si->si_code);
	}
	else
		stprintf(cfg, "--- stopped by %s ---\n", signame(sig));
}
