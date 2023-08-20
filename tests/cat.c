#include <stdio.h>
#include <unistd.h>

#define BUF_SIZE 1024

int main(void)
{
	ssize_t size;
	char buf[BUF_SIZE];

	while ((size = read(0, buf, BUF_SIZE)) > 0)
		write(1, buf, size);
	if (size < 0)
	{
		perror("read");
		return (1);
	}
	return (0);
}
