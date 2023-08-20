#include <stddef.h>
#include <unistd.h>

// To be compiled with gcc -m32 execvecat.c to check how strace handles a
// process switching back and forth between 32 and 64 bits.

int	main(void)
{
	execve("/bin/cat", (char *[]){"cat", NULL}, NULL);
	return (1);
}
