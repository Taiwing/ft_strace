#include "ft_strace.h"
#include <string.h>
#include <ctype.h>

static size_t	process_peekstr(pid_t pid, void *addr, void *buf, size_t len)
{
	void		*ptr;
	uint64_t	value;
	size_t		ret = 0, rd;

	while (len)
	{
		value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		rd = len > sizeof(value) ? sizeof(value) : len;
		memcpy(buf, &value, rd);
		if ((ptr = memchr(buf, 0, rd)))
		{
			rd = ptr - buf + 1;
			ret += rd;
			break ;
		}
		ret += rd;
		len -= rd;
		buf += rd;
		addr += rd;
	}
	return (ret);
}

static void		process_peekdata(pid_t pid, void *addr, void *buf, size_t len)
{
	size_t		rd;
	uint64_t	value;

	while (len)
	{
		value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		rd = len > sizeof(value) ? sizeof(value) : len;
		memcpy(buf, &value, rd);
		len -= rd;
		buf += rd;
		addr += rd;
	}
}

#define BUF_MAX			16
#define PRINT_MAX		(BUF_MAX * 4)
#define SPECIAL_PRINT	"\"\\"

static void		print_buf(int comma, uint64_t param, size_t size)
{
	int			written = 0;
	size_t		print_size = 0;
	char		buf[BUF_MAX + 1];
	char		print[PRINT_MAX + 1];

	size = size > BUF_MAX ? BUF_MAX + 1 : size;
	process_peekdata(g_cfg->current_process->pid, (void *)param,
		buf, size);
	for (size_t i = 0; i < BUF_MAX && i < size && print_size < PRINT_MAX; ++i)
	{
		if (!isprint(buf[i]) && buf[i] != '\n')
			written = snprintf(print + print_size,
				PRINT_MAX - print_size, "\\x%02hhx", buf[i]);
		else if (strchr(SPECIAL_PRINT, buf[i]))
			written = snprintf(print + print_size,
				PRINT_MAX - print_size, "\\%c", buf[i]);
		else if (buf[i] == '\n')
			written = snprintf(print + print_size,
				PRINT_MAX - print_size, "\\n");
		else
			written = snprintf(print + print_size,
				PRINT_MAX - print_size, "%c", buf[i]);
		if (written < 0)
			break ;
		print_size += written;
	}
	stprintf(NULL, "%s\"%.*s\"%s", comma ? ", " : "", (int)print_size, print,
		size > BUF_MAX ? "..." : "");
}

#define STR_MAX			32

static size_t	print_str(int comma, uint64_t param)
{
	size_t		size;
	char		buf[STR_MAX + 1];

	if (!param)
	{
		stprintf(NULL, "%sNULL", comma ? ", " : "");
		return (0);
	}
	size = process_peekstr(g_cfg->current_process->pid, (void *)param,
		buf, STR_MAX + 1);
	stprintf(NULL, "%s\"%.*s\"%s", comma ? ", " : "", (int)size, buf,
		size > STR_MAX ? "..." : "");
	return (size > STR_MAX ? STR_MAX : size);
}

static void		print_str_array(int comma, uint64_t param, enum e_arch arch)
{
	uint64_t	addr;

	stprintf(NULL, "%s%s", comma ? ", " : "", param ? "[" : "NULL");
	if (!param)
		return ;
	comma = 0;
	while (1)
	{
		addr = ptrace(PTRACE_PEEKDATA, g_cfg->current_process->pid, param, 0);
		if (arch == E_ARCH_32)
			addr = (uint32_t)addr;
		if (addr || !comma)
			print_str(comma, addr);
		if (!addr)
			break ;
		comma = 1;
		param += arch == E_ARCH_32 ? sizeof(uint32_t) : sizeof(uint64_t);
	}
	stprintf(NULL, "]");
}

static void		print_ptr(int comma, uint64_t param)
{
	if (param)
		stprintf(NULL, "%s%p", comma ? ", " : "", param);
	else
		stprintf(NULL, "%sNULL", comma ? ", " : "");
}

void			print_parameter(int comma, enum e_syscall_type type,
	uint64_t param, uint64_t size, enum e_arch arch)
{
	switch (type)
	{
		case TNONE: stprintf(NULL, "%s?", comma ? ", " : "");			break;
		case TINT:
		case TLINT: stprintf(NULL, "%s%ld", comma ? ", " : "", param);	break;
		case TUSHRT:
		case TUINT:
		case TLUINT: stprintf(NULL, "%s%lu", comma ? ", " : "", param);	break;
		case TPTR: print_ptr(comma, param);								break;
		case TSTR:
		case TWSTR: print_str(comma, param);							break;
		case TSCHAR:
		case TWSCHAR: print_buf(comma, param, size);					break;
		case TASTR: print_str_array(comma, param, arch);				break;
	}
}
