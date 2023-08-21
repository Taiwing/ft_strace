# ft\_strace

This is a re-implementation of the strace utility in C. This program executes a
given command and records every syscall done by the process as well as the
signals it receives. It is a useful debugging tool.

## Setup

```shell
# clone it
git clone https://github.com/Taiwing/ft_strace
# build id
cd ft_strace/ && make
# run it
./ft_strace ls -R
```

Some options might require sudo rights (-p). If you do not have root access on
your machine but docker is available, then execute the following commands to run
ft\_strace:

```shell
# build docker image and run it
./setup-docker.bash
# run ft_strace inside the container
./ft_strace cat
```

## Usage

```
Usage:
	ft_strace [-cChk] command [args]
	ft_strace [-cChk] -p pid [ command [args] ]

Options:
	-c, --summary-only
		Report only a summary of time, call and error counts per syscall.
	-C, --summary
		Like -c but also print regular output while processes are running.
	-h, --help
		Print this.
	-k, --kernel-time
		Use time spent in the kernel instead of wall-clock for summary options.
	-p, --attach=pid
		Attach to the process with the process ID 'pid' and begin tracing.
```

### example

```C
int main(void) { return (0); }
```

```shell
# compile the test program above
gcc test.c
# list its syscalls
./ft_strace ./a.out
```

possible output:

```
execve("./a.out", ["./a.out"], 0x7fffbdf8c510) = 0
brk(NULL) = 0x563b4068a000
arch_prctl(12289, 140734339306160) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", 4) = -1 ENOENT (No such file or directory)
openat(4294967196, "/etc/ld.so.cache", 524288, 0) = 3
newfstatat(3, "", 0x7fff444d44e0, 4096) = 0
mmap(NULL, 151155, 1, 2, 3, 0) = 0x7fed9ddeb000
close(3) = 0
openat(4294967196, "/usr/lib/libc.so.6", 524288, 0) = 3
read(3, "\x7fELF\x02\x01\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00"..., 832) = 832
pread64(3, "\x06\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00"..., 784, 64) = 784
newfstatat(3, "", 0x7fff444d44e0, 4096) = 0
mmap(NULL, 8192, 3, 34, 4294967295, 0) = 0x7fed9dde9000
pread64(3, "\x06\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00"..., 784, 64) = 784
mmap(NULL, 2006640, 1, 2050, 3, 0) = 0x7fed9dbff000
mmap(0x7fed9dc21000, 1429504, 5, 2066, 3, 139264) = 0x7fed9dc21000
mmap(0x7fed9dd7e000, 360448, 1, 2066, 3, 1568768) = 0x7fed9dd7e000
mmap(0x7fed9ddd6000, 24576, 3, 2066, 3, 1925120) = 0x7fed9ddd6000
mmap(0x7fed9dddc000, 52848, 3, 50, 4294967295, 0) = 0x7fed9dddc000
close(3) = 0
mmap(NULL, 8192, 3, 34, 4294967295, 0) = 0x7fed9dbfd000
arch_prctl(4098, 140658532591168) = 0
set_tid_address(0x7fed9ddea910) = 68377
set_robust_list(0x7fed9ddea920, 24) = 0
rseq(0x7fed9ddeaf60, 32, 0, 1392848979) = 0
mprotect(0x7fed9ddd6000, 16384, 1) = 0
mprotect(0x563b3ebb0000, 4096, 1) = 0
mprotect(0x7fed9de41000, 8192, 1) = 0
prlimit64(0, 3, NULL, 0x7fff444d5020) = 0
munmap(0x7fed9ddeb000, 151155) = 0
exit_group(0) = ?
+++ exited with 0 +++
```
