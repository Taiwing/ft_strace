#include "ft_strace.h"
#include <string.h>
#include <limits.h>

#define ACCESS_TEST_ENOTFOUND	-1
#define ACCESS_TEST_ENOTEXEC	-2

static int	access_test(char *cmd_name)
{
	if (access(cmd_name, F_OK))
		return (ACCESS_TEST_ENOTFOUND);
	else if (access(cmd_name, X_OK) < 0)
	{
		warn("'%s'", cmd_name);
		return (ACCESS_TEST_ENOTEXEC);
	}
	return (0);
}

static char	*find_file_path(char *dest, char *path, char *cmd_name)
{
	int	ret;

	for (char *p = strtok(path, ":"); p; p = strtok(NULL, ":"))
	{
		if (strlen(p) + 1 + strlen(cmd_name) > PATH_MAX - 1)
		{
			warnx("'%s': path too long, skipping it", p);
			continue ;
		}
		strcat(strcat(strcpy(dest, p), "/"), cmd_name);
		if (!(ret = access_test(dest)))
			return (dest);
		else if (ret == ACCESS_TEST_ENOTEXEC)
			return (NULL);
	}
	return (NULL);
}

#define PATH_BUF_MAX	(PATH_MAX * 16)

char		*find_command(char *cmd_name)
{
	char		*local, *path;
	static char	cmd_path[PATH_MAX];
	char		path_buf[PATH_BUF_MAX];

	if ((local = strchr(cmd_name, '/')))
		return (!access_test(cmd_name) ? cmd_name : NULL);
	else if (!(path = getenv("PATH")))
	{
		warnx("PATH is not set");
		return (NULL);
	}
	else if (strlen(path) > PATH_BUF_MAX - 1)
	{
		warnx("PATH too long");
		return (NULL);
	}
	else if (strlen(cmd_name) > PATH_MAX - 1)
	{
		warnx("command name too long");
		return (NULL);
	}
	strncpy(path_buf, path, PATH_BUF_MAX);
	return (find_file_path(cmd_path, path_buf, cmd_name));
}
