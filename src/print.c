#include "ft_strace.h"

int	stprintf(t_st_config *cfg, const char *format, ...)
{
	va_list		args;
	int			ret;

	if (cfg && cfg->process_count > 1)
		fprintf(stderr, "[pid %5u] ", cfg->current_pid);
	va_start(args, format);
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return (ret);
}
