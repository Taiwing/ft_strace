#include "ft_strace.h"
#include <string.h>

size_t	parse_pid_list(pid_t **dest, char *pid_argument)
{
	static size_t	size = 0;
	size_t			ret = 0;
	pid_t			pid = 0;
	char			*token = NULL, *tail = NULL;

	if (!size && (!pid_argument || !(token = strtok(pid_argument, ", "))))
		error(EXIT_FAILURE, EINVAL, __func__);
	else if (!size || !!(token = strtok(pid_argument, ", ")))
	{
		errno = 0;
		pid = (pid_t)strtol(token, &tail, 0);
		if (pid < 0 || tail == token || *tail != '\0')
			error(EXIT_FAILURE, EINVAL, "%s: '%s'", __func__, token);
		size += 1;
		ret = parse_pid_list(dest, NULL);
		(*dest)[--size] = pid;
	}
	else if (!(*dest = malloc(size * sizeof(pid_t))))
		err(EXIT_FAILURE, __func__);
	else
		ret = size;
	return (ret);
}
