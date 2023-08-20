#include "ft_strace.h"
#include <string.h>
#include <sys/param.h>

#define COL_COUNT 6

const char			*g_summary_columns[COL_COUNT] = {
	"% time", "seconds", "usecs/call", "calls", "errors", "syscall"
};

static int			compare_summary(const void *a, const void *b)
{
	const t_st_summary	*sa = a;
	const t_st_summary	*sb = b;

	if (!sa->calls || !sb->calls)
		return (sb->calls - sa->calls);
	else if (sa->time.tv_sec == sb->time.tv_sec)
		return (sb->time.tv_usec - sa->time.tv_usec);
	return (sb->time.tv_sec - sa->time.tv_sec);
}

static int			intlen(uint64_t n)
{
	int	len = 1;

	while (n /= 10)
		++len;
	return (len);
}

static void			get_summary_data(int *width, uint64_t *total,
	t_st_summary *summary, size_t size, const t_syscall *syscalls)
{
	char		*name;
	//double		seconds;
	char		bufname[256];
	//uint64_t	usecs, calls, errors;
	uint64_t	calls, errors;

	total[0] = 100;
	total[1] = total[2] = 0;
	for (size_t i = 0; i < size && summary[i].calls; ++i)
	{
		//seconds = (double)summary[i].time.tv_sec
		//	+ (double)summary[i].time.tv_usec / 1000000000.0;
		//usecs = summary[i].time.tv_sec * 1000000 + summary[i].time.tv_usec / 1000;
		calls = summary[i].calls;
		errors = summary[i].errors;
		//width[1] = MAX(width[1], ft_nbrlen((uint64_t)seconds, 10));
		//width[2] = MAX(width[2], ft_nbrlen(usecs / calls, 10));
		width[3] = MAX(width[3], intlen(calls));
		width[4] = MAX(width[4], intlen(errors));
		if (syscalls[summary[i].syscall].name)
			name = syscalls[summary[i].syscall].name;
		else
		{
			name = bufname;
			snprintf(bufname, sizeof(bufname),
				"unknown(%d)", summary[i].syscall);
		}
		width[5] = MAX(width[5], strlen(name) + 1);
		total[3] += calls;
		total[4] += errors;
	}
}

static void			print_separator(int *width)
{
	char	sep[256] = { [0 ... 255] = '-' };

	for (int i = 0; i < COL_COUNT; ++i)
		width[i] = MIN(width[i], sizeof(sep));
	stprintf(NULL, "%1$.*2$s %1$.*3$s %1$.*4$s %1$.*5$s %1$.*6$s %1$.*7$s\n",
		sep, width[0], width[1], width[2], width[3], width[4], width[5]);
}

static void			print_summary_table(t_st_summary *summary, size_t size,
	const t_syscall *syscalls)
{
	uint64_t	total[COL_COUNT] = { 0 };
	int			width[COL_COUNT] = {
		[0] = strlen(g_summary_columns[0]),
		[1] = strlen(g_summary_columns[1]) + 4,
		[2] = strlen(g_summary_columns[2]) + 1,
		[3] = strlen(g_summary_columns[3]) + 4,
		[4] = strlen(g_summary_columns[4]) + 3,
		[5] = strlen(g_summary_columns[5])
	};

	qsort(summary, size, sizeof(t_st_summary), compare_summary);
	get_summary_data(width, total, summary, size, syscalls);
	stprintf(NULL, "%*s %*s %*s %*s %*s %s\n",
		width[0], g_summary_columns[0], width[1], g_summary_columns[1],
		width[2], g_summary_columns[2], width[3], g_summary_columns[3],
		width[4], g_summary_columns[4], g_summary_columns[5]);
	print_separator(width);
	for (size_t i = 0; i < size && summary[i].calls; ++i)
	{
		uint64_t calls = summary[i].calls;
		uint64_t errors = summary[i].errors;
		stprintf(NULL, "%*.2f %*.6f %*llu %*llu", width[0], 0.0,
			width[1], 0.0, width[2], 0ULL, width[3], calls);
		if (errors)
			stprintf(NULL, " %*llu", width[4], errors);
		else
			stprintf(NULL, " %*s", width[4], "");
		if (syscalls[summary[i].syscall].name)
			stprintf(NULL, " %s\n", syscalls[summary[i].syscall].name);
		else
			stprintf(NULL, " unknown(%d)\n", summary[i].syscall);
	}
	print_separator(width);
	stprintf(NULL, "%*.2f %*llu %*llu %*llu %*llu total\n", width[0], 100.0,
		width[1], 0ULL, width[2], 0ULL, width[3], total[3], width[4], total[4]);
}

void				print_summary(t_st_config *cfg)
{
	print_summary_table(cfg->summary_64, G_SYSCALL_X86_64, g_syscall_x86_64);
	if (cfg->arch_changed)
	{
		stprintf(NULL, "System call usage summary for 32 bit mode:\n");
		print_summary_table(cfg->summary_32,
			G_SYSCALL_X86_I386, g_syscall_x86_i386);
	}
}

static t_st_summary	*get_summary(t_st_config *cfg, t_st_process *process)
{
	enum e_arch		arch;
	int				syscall;

	if (!process->in_syscall)
		return (NULL);
	if (process->arch_changed)
	{
		arch = process->arch == E_ARCH_32 ? E_ARCH_64 : E_ARCH_32;
		syscall = process->last_syscall;
	}
	else
	{
		arch = process->arch;
		syscall = process->current_syscall;
	}
	if (syscall < 0 || (arch == E_ARCH_32 && syscall >= G_SYSCALL_X86_I386)
		|| (arch == E_ARCH_64 && syscall >= G_SYSCALL_X86_64))
		return (NULL);
	return (arch == E_ARCH_32 ? &cfg->summary_32[syscall]
		: &cfg->summary_64[syscall]);
}

void			count_syscall(t_st_config *cfg, t_st_process *process)
{
	t_st_summary	*summary;
	uint64_t		return_value;

	if (!(summary = get_summary(cfg, process)))
		return ;
	return_value = process->arch == E_ARCH_32 ? process->regs.regs32.eax
		: process->regs.regs64.rax;
	++summary->calls;
	summary->errors += syscall_error_return(return_value, process->arch);
}

void			init_summary(t_st_config *cfg)
{
	for (int i = 0; i < G_SYSCALL_X86_I386; ++i)
		cfg->summary_32[i].syscall = i;
	for (int i = 0; i < G_SYSCALL_X86_64; ++i)
		cfg->summary_64[i].syscall = i;
}
