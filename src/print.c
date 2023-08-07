#include "ft_strace.h"

int	ft_strace_printf(t_st_config *cfg, const char *format, ...)
{
	va_list		args;
	int			ret;

	if (cfg->process_count > 1)
		fprintf(cfg->output, "[pid %5u] ", cfg->current_pid);
	va_start(args, format);
	ret = vfprintf(cfg->output, format, args);
	va_end(args);
	return (ret);
}
