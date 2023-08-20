#include "ft_strace.h"
#include <string.h>
#include <sys/param.h>

#define COL_COUNT 6
#define STRLEN(s) (strlen(s))

/*
** Summary column names
*/
const char			*g_summary_columns[COL_COUNT] = {
	"% time", "seconds", "usecs/call", "calls", "errors", "syscall"
};

/*
** Default column width
*/
const int			default_width[COL_COUNT] = {
	[0] = 6, [1] = 11, [2] = 11, [3] = 9, [4] = 9, [5] = 7
};

/*
** Summary total structure (last line)
*/
typedef struct	s_summary_total {
	double		time;
	double		seconds;
	uint64_t	usecs;
	uint64_t	calls;
	uint64_t	errors;
}				t_summary_total;

static int			compare_summary(const void *a, const void *b)
{
	const t_st_summary	*sa = a;
	const t_st_summary	*sb = b;

	if (!sa->calls || !sb->calls)
		return (sb->calls - sa->calls);
	else if (sa->total.tv_sec == sb->total.tv_sec)
		return (sb->total.tv_nsec - sa->total.tv_nsec);
	return (sb->total.tv_sec - sa->total.tv_sec);
}

static int			intlen(uint64_t n)
{
	int	len = 1;

	while (n /= 10)
		++len;
	return (len);
}

static void			get_summary_data(int *width, t_summary_total *total,
	t_st_summary *summary, size_t size, const t_syscall *syscalls)
{
	char		*name;
	char		bufname[256];

	total->time = 100.0;
	for (size_t i = 0; i < size && summary[i].calls; ++i)
	{
		summary[i].time = ts_to_second(&summary[i].total);
		summary[i].avgtime =
			(uint64_t)ts_to_usec(&summary[i].total) / summary[i].calls;
		width[3] = MAX(width[3], intlen(summary[i].calls));
		width[4] = MAX(width[4], intlen(summary[i].errors));
		if (syscalls[summary[i].syscall].name)
			name = syscalls[summary[i].syscall].name;
		else
		{
			name = bufname;
			snprintf(bufname, sizeof(bufname),
				"unknown(%d)", summary[i].syscall);
		}
		width[5] = MAX(width[5], strlen(name) + 1);
		total->seconds += summary[i].time;
		total->calls += summary[i].calls;
		total->errors += summary[i].errors;
	}
	total->usecs = (uint64_t)(total->seconds * USEC_PER_SEC) / total->calls;
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
	double			time = 0.0;
	t_summary_total	total = { 0 };
	int				width[COL_COUNT] = { 0 };

	memcpy(width, default_width, sizeof(width));
	qsort(summary, size, sizeof(t_st_summary), compare_summary);
	get_summary_data(width, &total, summary, size, syscalls);
	stprintf(NULL, "%*s %*s %*s %*s %*s %s\n",
		width[0], g_summary_columns[0], width[1], g_summary_columns[1],
		width[2], g_summary_columns[2], width[3], g_summary_columns[3],
		width[4], g_summary_columns[4], g_summary_columns[5]);
	print_separator(width);
	for (size_t i = 0; i < size && summary[i].calls; ++i)
	{
		if (total.seconds != 0.0)
			time = summary[i].time / total.seconds * 100.0;
		stprintf(NULL, "%*.2f %*.6f %*llu %*llu", width[0], time, width[1],
			summary[i].time, width[2], summary[i].avgtime,
			width[3], summary[i].calls);
		if (summary[i].errors)
			stprintf(NULL, " %*llu", width[4], summary[i].errors);
		else
			stprintf(NULL, " %*s", width[4], "");
		if (syscalls[summary[i].syscall].name)
			stprintf(NULL, " %s\n", syscalls[summary[i].syscall].name);
		else
			stprintf(NULL, " unknown(%d)\n", summary[i].syscall);
	}
	print_separator(width);
	stprintf(NULL, "%*.2f %*.6f %*llu %*llu %*llu total\n",
		width[0], total.time, width[1], total.seconds, width[2], total.usecs,
		width[3], total.calls, width[4], total.errors);
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
