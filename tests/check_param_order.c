#include <unistd.h>
#include <sys/syscall.h>

int	main(void)
{
	syscall(__NR_sendto, 0, 1, 2, 3, 4, 5);
	return (0);
}
