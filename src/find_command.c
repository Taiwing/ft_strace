#include "ft_strace.h"
#include <string.h>

/*
** Attempt to find the given command in the PATH.
**
** dest: pointer to the complete command path if it is found, NULL otherwise
** path: PATH value
** cmd_name: name of the command to find
**
** Returns 1 if a fatal error has occured (failed allocation), 0 otherwise. Note
** that the 'real' result of this function is passed through the 'dest'
** parameter. This is because a command not found is a 'warn' level error not a
** fatal one for which this program should exit.
*/
static int	find_file_path(char **dest, char *path, char *cmd_name)
{
	char	*fp = NULL;

	*dest = NULL;
	for (char *p = strtok(path, ":"); p; p = strtok(NULL, ":"))
	{
		if (!(fp = calloc(strlen(p) + 2 + strlen(cmd_name), sizeof(char))))
		{
			warn("calloc");
			return (1);
		}
		strcat(strcat(strcat(fp, p), "/"), cmd_name);
		if (!access(fp, F_OK))
		{
			if (access(fp, X_OK) == -1)
			{
				warn("'%s'", cmd_name);
				free(fp);
				fp = NULL;
			}
			*dest = fp;
			return (0);
		}
		free(fp);
	}
	warnx("'%s': command not found", cmd_name);
	return (0);
}

static int	access_test(char *cmd_name)
{
	if (access(cmd_name, F_OK))
		warnx("'%s': command not found", cmd_name);
	else if (access(cmd_name, X_OK) == -1)
		warn("'%s'", cmd_name);
	else
		return (0);
	return (1);
}

/*
** Find a command on PATH if need be.
**
** cmd_name: name or path of the command to find
**
** Returns NULL if the path is not valid or if the command was not found,
** otherwise it returns its path as an allocated string. This function will
** exit if a fatal error occurs (an allocation error).
*/
char	*find_command(char *cmd_name)
{
	int		ret;
	char	*local, *path;
	char	*cmd_path = NULL;

	if ((local = strchr(cmd_name, '/')) && !access_test(cmd_name))
	{
		if (!(cmd_path = strdup(cmd_name)))
			err(EXIT_FAILURE, "strdup");
	}
	else if (!local && (path = getenv("PATH")))
	{
		if (!(path = strdup(path)))
			err(EXIT_FAILURE, "strdup");
		ret = find_file_path(&cmd_path, path, cmd_name);
		free(path);
		if (ret)
			exit(EXIT_FAILURE);
	}
	return (cmd_path);
}
