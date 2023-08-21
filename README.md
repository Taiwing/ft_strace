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

> This is program is made to be compiled and run on a linux x86\_64 system. It
> has not been tested on any other architecture and is not expected to work
> under any other one. However, it is still possible to trace 32bit processes.

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

By default ft\_strace will print each syscall and their parameter until the
tracee is killed or exits. It will also show the return value and an eventual
error if the syscall failed. If you just want a list of the syscalls without all
the detail you can run this program with the summary option:

```shell
./ft_strace -c ls
```

possible output:

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.94    0.000416         416         1           execve
 12.52    0.000127          63         2         1 arch_prctl
 10.62    0.000108          36         3           brk
  9.41    0.000096           7        13           mmap
  3.97    0.000040           5         7           close
  3.61    0.000037           7         5           openat
  3.36    0.000034           5         6           newfstatat
  3.00    0.000031          15         2           getdents64
  2.33    0.000024          23         1           write
  2.30    0.000023           5         4           mprotect
  1.90    0.000019           3         6         4 prctl
  0.90    0.000009           9         1           munmap
  0.87    0.000009           8         1         1 access
  0.80    0.000008           8         1         1 ioctl
  0.75    0.000008           7         1           getrandom
  0.75    0.000008           3         2           read
  0.68    0.000007           3         2           pread64
  0.34    0.000003           3         1           prlimit64
  0.32    0.000003           3         1           set_robust_list
  0.32    0.000003           3         1           rseq
  0.32    0.000003           3         1           set_tid_address
------ ----------- ----------- --------- --------- ----------------
100.00    0.001017          16        62         7 total
```

Contrary to the original strace, this program uses wall-clock time by default
(meaning the real time as per the system clock visible to the user). To use the
same clock as the original, ther kernel clock, pass -k with one of the summary
options.

## Description

The command argument can be any valid program followed by its own arguments.
ft\_strace can be given an absolute path to an executable file or it will search
the binary location with the PATH environment variable. ft\_strace own options
must absolutely be given before the command, otherwise it will pas them to the
executed command.

If no command is given ft\_strace expects the --attach (-p) option with a list
of comma or space separated pids. Typically this can be used with the output of
the *pidof* command:

```shell
# run some cat commands
cat & cat
# attach ft_strace to them in an other shell
sudo ./ft_strace -p "$(pidof cat)"
```

ft\_strace will then proceed to trace every running instance of the *cat*
command. Each output line will be preceeded with the pid of the process it
refers to until only one process remains:

```
ft_strace: Process 69169 attached
ft_strace: Process 69168 attached
[pid 69168] --- stopped by SIGTTIN ---
[pid 69169] read(0, "toto\n", 131072) = 5
[pid 69169] write(1, "toto\n", 5) = 5
[pid 69169] read(0, "", 131072) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
[pid 69169] --- SIGTSTP {si_signo=SIGTSTP, si_code=SI_KERNEL} ---
[pid 69169] --- stopped by SIGTSTP ---
[pid 69169] --- SIGCONT {si_signo=SIGCONT, si_code=SI_USER, si_pid=52291, si_uid=1000} ---
[pid 69169] read(0, "", 131072) = 0
[pid 69169] munmap(0x7f0394349000, 139264) = 0
[pid 69169] close(0) = 0
[pid 69169] close(1) = 0
[pid 69169] close(2) = 0
[pid 69169] exit_group(0) = ?
[pid 69169] +++ exited with 0 +++
--- SIGCONT {si_signo=SIGCONT, si_code=SI_USER, si_pid=52291, si_uid=1000} ---
read(0, "", 131072) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
--- SIGINT {si_signo=SIGINT, si_code=SI_KERNEL} ---
+++ killed by SIGINT +++
```

> As shown above, seizing a running process for tracing requires sudo rights.
> Refer to the [Setup](#setup) section to run this program in a container.

## How it works

This program observes a running process and lists each
[system call](https://en.wikipedia.org/wiki/System_call) with the
[ptrace()](https://man7.org/linux/man-pages/man2/ptrace.2.html) function (which
actually is a system call too). After having seized a process it will use the
[wait4()](https://man7.org/linux/man-pages/man2/wait4.2.html) system call to
wait for events.

### What is a system call

System calls are a userspace to kernel interface. They allow regular user
processes to access system functionalities. The
[Kernel](https://en.wikipedia.org/wiki/Linux_kernel) is a program that is always
running. It acts as bridge between the OS and the hardware. Thus it handles
everything memory-related, networking, etc... It also spawns and kills
processes or sends signals for example.

They include _open()_, _read()_, _write()_, or _fork()_ and _execve()_... The
complete [list](https://x64.syscall.sh/) contains more than 300 different system
calls. Most of them are accessible through glibc wrapper functions that somewhat
abstract the interface for compatibility between architectures. Some of them do
not have corresponding wrappers and have to be called with the
[syscall()](https://man7.org/linux/man-pages/man2/syscall.2.html) function.

In its most basic form a linux system call is an assembly instruction, an
interruption for legacy 32bit systems and the *syscall* instruction for x86\_64
systems. The particular system called being used is designated by a unique
syscall number that is passed in a particular register (*eax* for i386 and *rax*
for x86\_64). It takes at most 6 parameters through six other registers. On
different processor architectures different syscall numbers and register sets
will be used. Some might even have system calls that do not exist on an other
one. Or they could also implement the same system call in different ways. A
particularly egregious example of that is the _clone()_ system call. It has
[four different definitions](https://github.com/torvalds/linux/blob/master/kernel/fork.c#L3022)
including three that have five parameters in varying order and one with six
parameters.

Most of that is abstracted for the final user that should not have to worry
about it. However it is important to keep in mind when dealing with different
architectures in a low level setting. This one of the reason that ft\_strace
only works on the x86\_64 architecture.

### How to catch a system call ?

With _ptrace()_. But first you have to *seize* the running process you want to
observe. For that one simply has to use the *PTRACE_SEIZE* request on the pid of
the chosen process:

```C
ptrace(PTRACE_SEIZE, pid, NULL, NULL);
```

Then if the process has appropriate rights, or if the pid corresponds to a child
process, the target process will be traced. If the tracee is not already stopped
it will have to be done with an other *ptrace()* request (*PTRACE_INTERRUPT*).
Then the process can be restarted using this request:

```C
ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
```

It will both restart the process and make it stop on the next syscall entry.
From there ft\_strace simply waits for events with the _wait4()_ function. Every
system call entry and exit of the tracee will be reported back to ft\_strace, as
well as the signals it receives and eventually its death (be it by _exit()_ or
by a signal).
