#include "syscall.h"

const t_syscall	g_syscall_x86_64[G_SYSCALL_X86_64]= {
	[0] = { "read", TLINT, { TUINT, TWSCHAR, TLUINT, TNONE, TNONE, TNONE } },
	[1] = { "write", TLINT, { TUINT, TSCHAR, TLUINT, TNONE, TNONE, TNONE } },
	[2] = { "open", TLINT, { TSTR, TINT, TUSHRT, TNONE, TNONE, TNONE } },
	[3] = { "close", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[4] = { "stat", TLINT, { TSTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[5] = { "fstat", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[6] = { "lstat", TLINT, { TSTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[7] = { "poll", TLINT, { TPTR, TUINT, TINT, TNONE, TNONE, TNONE } },
	[8] = { "lseek", TLINT, { TUINT, TLINT, TUINT, TNONE, TNONE, TNONE } },
	[9] = { "mmap", TPTR, { TPTR, TLUINT, TLUINT, TLUINT, TLUINT, TLUINT } },
	[10] = { "mprotect", TLINT, { TPTR, TLUINT, TLUINT, TNONE, TNONE, TNONE } },
	[11] = { "munmap", TLINT, { TPTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[12] = { "brk", TPTR, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[13] = { "rt_sigaction", TLINT, { TINT, TPTR, TPTR, TLUINT, TNONE, TNONE } },
	[14] = { "rt_sigprocmask", TLINT, { TINT, TPTR, TPTR, TLUINT, TNONE, TNONE } },
	[15] = { "rt_sigreturn", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[16] = { "ioctl", TLINT, { TUINT, TUINT, TLUINT, TNONE, TNONE, TNONE } },
	[17] = { "pread64", TLINT, { TUINT, TWSCHAR, TLUINT, TLINT, TNONE, TNONE } },
	[18] = { "pwrite64", TLINT, { TUINT, TSCHAR, TLUINT, TLINT, TNONE, TNONE } },
	[19] = { "readv", TLINT, { TLUINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[20] = { "writev", TLINT, { TLUINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[21] = { "access", TLINT, { TSTR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[22] = { "pipe", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[23] = { "select", TLINT, { TINT, TPTR, TPTR, TPTR, TPTR, TNONE } },
	[24] = { "sched_yield", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[25] = { "mremap", TLINT, { TLUINT, TLUINT, TLUINT, TLUINT, TLUINT, TNONE } },
	[26] = { "msync", TLINT, { TLUINT, TLUINT, TINT, TNONE, TNONE, TNONE } },
	[27] = { "mincore", TLINT, { TLUINT, TLUINT, TPTR, TNONE, TNONE, TNONE } },
	[28] = { "madvise", TLINT, { TLUINT, TLUINT, TINT, TNONE, TNONE, TNONE } },
	[29] = { "shmget", TLINT, { TINT, TLUINT, TINT, TNONE, TNONE, TNONE } },
	[30] = { "shmat", TLINT, { TINT, TPTR, TINT, TNONE, TNONE, TNONE } },
	[31] = { "shmctl", TLINT, { TINT, TINT, TPTR, TNONE, TNONE, TNONE } },
	[32] = { "dup", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[33] = { "dup2", TLINT, { TUINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[34] = { "pause", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[35] = { "nanosleep", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[36] = { "getitimer", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[37] = { "alarm", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[38] = { "setitimer", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[39] = { "getpid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[40] = { "sendfile", TLINT, { TINT, TINT, TPTR, TLUINT, TNONE, TNONE } },
	[41] = { "socket", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[42] = { "connect", TLINT, { TINT, TPTR, TINT, TNONE, TNONE, TNONE } },
	[43] = { "accept", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[44] = { "sendto", TLINT, { TINT, TPTR, TLUINT, TUINT, TPTR, TINT } },
	[45] = { "recvfrom", TLINT, { TINT, TPTR, TLUINT, TUINT, TPTR, TPTR } },
	[46] = { "sendmsg", TLINT, { TINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[47] = { "recvmsg", TLINT, { TINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[48] = { "shutdown", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[49] = { "bind", TLINT, { TINT, TPTR, TINT, TNONE, TNONE, TNONE } },
	[50] = { "listen", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[51] = { "getsockname", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[52] = { "getpeername", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[53] = { "socketpair", TLINT, { TINT, TINT, TINT, TPTR, TNONE, TNONE } },
	[54] = { "setsockopt", TLINT, { TINT, TINT, TINT, TSCHAR, TINT, TNONE } },
	[55] = { "getsockopt", TLINT, { TINT, TINT, TINT, TPTR, TPTR, TNONE } },
	[56] = { "clone", TLINT, { TLUINT, TLUINT, TPTR, TPTR, TLUINT, TNONE } },
	[57] = { "fork", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[58] = { "vfork", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[59] = { "execve", TLINT, { TSTR, TASTR, TPTR, TNONE, TNONE, TNONE } },
	[60] = { "exit", TNONE, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[61] = { "wait4", TLINT, { TINT, TPTR, TINT, TPTR, TNONE, TNONE } },
	[62] = { "kill", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[63] = { "uname", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[64] = { "semget", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[65] = { "semop", TLINT, { TINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[66] = { "semctl", TLINT, { TINT, TINT, TINT, TLUINT, TNONE, TNONE } },
	[67] = { "shmdt", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[68] = { "msgget", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[69] = { "msgsnd", TLINT, { TINT, TPTR, TLUINT, TINT, TNONE, TNONE } },
	[70] = { "msgrcv", TLINT, { TINT, TPTR, TLUINT, TLINT, TINT, TNONE } },
	[71] = { "msgctl", TLINT, { TINT, TINT, TPTR, TNONE, TNONE, TNONE } },
	[72] = { "fcntl", TLINT, { TUINT, TUINT, TLUINT, TNONE, TNONE, TNONE } },
	[73] = { "flock", TLINT, { TUINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[74] = { "fsync", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[75] = { "fdatasync", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[76] = { "truncate", TLINT, { TSTR, TLINT, TNONE, TNONE, TNONE, TNONE } },
	[77] = { "ftruncate", TLINT, { TUINT, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[78] = { "getdents", TLINT, { TUINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[79] = { "getcwd", TLINT, { TWSTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[80] = { "chdir", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[81] = { "fchdir", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[82] = { "rename", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[83] = { "mkdir", TLINT, { TSTR, TUSHRT, TNONE, TNONE, TNONE, TNONE } },
	[84] = { "rmdir", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[85] = { "creat", TLINT, { TSTR, TUSHRT, TNONE, TNONE, TNONE, TNONE } },
	[86] = { "link", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[87] = { "unlink", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[88] = { "symlink", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[89] = { "readlink", TLINT, { TSTR, TWSCHAR, TINT, TNONE, TNONE, TNONE } },
	[90] = { "chmod", TLINT, { TSTR, TUSHRT, TNONE, TNONE, TNONE, TNONE } },
	[91] = { "fchmod", TLINT, { TUINT, TUSHRT, TNONE, TNONE, TNONE, TNONE } },
	[92] = { "chown", TLINT, { TSTR, TINT, TINT, TNONE, TNONE, TNONE } },
	[93] = { "fchown", TLINT, { TUINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[94] = { "lchown", TLINT, { TSTR, TINT, TINT, TNONE, TNONE, TNONE } },
	[95] = { "umask", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[96] = { "gettimeofday", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[97] = { "getrlimit", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[98] = { "getrusage", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[99] = { "sysinfo", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[100] = { "times", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[101] = { "ptrace", TLINT, { TLINT, TLINT, TLUINT, TLUINT, TNONE, TNONE } },
	[102] = { "getuid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[103] = { "syslog", TLINT, { TINT, TPTR, TINT, TNONE, TNONE, TNONE } },
	[104] = { "getgid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[105] = { "setuid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[106] = { "setgid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[107] = { "geteuid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[108] = { "getegid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[109] = { "setpgid", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[110] = { "getppid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[111] = { "getpgrp", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[112] = { "setsid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[113] = { "setreuid", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[114] = { "setregid", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[115] = { "getgroups", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[116] = { "setgroups", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[117] = { "setresuid", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[118] = { "getresuid", TLINT, { TPTR, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[119] = { "setresgid", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[120] = { "getresgid", TLINT, { TPTR, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[121] = { "getpgid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[122] = { "setfsuid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[123] = { "setfsgid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[124] = { "getsid", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[125] = { "capget", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[126] = { "capset", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[127] = { "rt_sigpending", TLINT, { TPTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[128] = { "rt_sigtimedwait", TLINT, { TPTR, TPTR, TPTR, TLUINT, TNONE, TNONE } },
	[129] = { "rt_sigqueueinfo", TLINT, { TINT, TINT, TPTR, TNONE, TNONE, TNONE } },
	[130] = { "rt_sigsuspend", TLINT, { TPTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[131] = { "sigaltstack", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[132] = { "utime", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[133] = { "mknod", TLINT, { TSTR, TUSHRT, TUINT, TNONE, TNONE, TNONE } },
	[134] = { "uselib", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[135] = { "personality", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[136] = { "ustat", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[137] = { "statfs", TLINT, { TSTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[138] = { "fstatfs", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[139] = { "sysfs", TLINT, { TINT, TLUINT, TLUINT, TNONE, TNONE, TNONE } },
	[140] = { "getpriority", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[141] = { "setpriority", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[142] = { "sched_setparam", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[143] = { "sched_getparam", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[144] = { "sched_setscheduler", TLINT, { TINT, TINT, TPTR, TNONE, TNONE, TNONE } },
	[145] = { "sched_getscheduler", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[146] = { "sched_get_priority_max", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[147] = { "sched_get_priority_min", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[148] = { "sched_rr_get_interval", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[149] = { "mlock", TLINT, { TLUINT, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[150] = { "munlock", TLINT, { TLUINT, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[151] = { "mlockall", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[152] = { "munlockall", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[153] = { "vhangup", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[154] = { "modify_ldt", TLINT, { TINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[155] = { "pivot_root", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[156] = { "_sysctl", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[157] = { "prctl", TLINT, { TINT, TLUINT, TLUINT, TLUINT, TLUINT, TNONE } },
	[158] = { "arch_prctl", TLINT, { TINT, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[159] = { "adjtimex", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[160] = { "setrlimit", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[161] = { "chroot", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[162] = { "sync", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[163] = { "acct", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[164] = { "settimeofday", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[165] = { "mount", TLINT, { TSTR, TSTR, TSTR, TLUINT, TPTR, TNONE } },
	[166] = { "umount2", TLINT, { TSTR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[167] = { "swapon", TLINT, { TSTR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[168] = { "swapoff", TLINT, { TSTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[169] = { "reboot", TLINT, { TINT, TINT, TUINT, TPTR, TNONE, TNONE } },
	[170] = { "sethostname", TLINT, { TSCHAR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[171] = { "setdomainname", TLINT, { TSCHAR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[172] = { "iopl", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[173] = { "ioperm", TLINT, { TLUINT, TLUINT, TINT, TNONE, TNONE, TNONE } },
	[174] = { "create_module", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[175] = { "init_module", TLINT, { TPTR, TLUINT, TSTR, TNONE, TNONE, TNONE } },
	[176] = { "delete_module", TLINT, { TSTR, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[177] = { "get_kernel_syms", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[178] = { "query_module", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[179] = { "quotactl", TLINT, { TUINT, TSTR, TUINT, TPTR, TNONE, TNONE } },
	[180] = { "nfsservctl", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[181] = { "getpmsg", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[182] = { "putpmsg", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[183] = { "afs_syscall", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[184] = { "tuxcall", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[185] = { "security", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[186] = { "gettid", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[187] = { "readahead", TLINT, { TINT, TLINT, TLUINT, TNONE, TNONE, TNONE } },
	[188] = { "setxattr", TLINT, { TSTR, TSTR, TPTR, TLUINT, TINT, TNONE } },
	[189] = { "lsetxattr", TLINT, { TSTR, TSTR, TPTR, TLUINT, TINT, TNONE } },
	[190] = { "fsetxattr", TLINT, { TINT, TSTR, TPTR, TLUINT, TINT, TNONE } },
	[191] = { "getxattr", TLINT, { TSTR, TSTR, TPTR, TLUINT, TNONE, TNONE } },
	[192] = { "lgetxattr", TLINT, { TSTR, TSTR, TPTR, TLUINT, TNONE, TNONE } },
	[193] = { "fgetxattr", TLINT, { TINT, TSTR, TPTR, TLUINT, TNONE, TNONE } },
	[194] = { "listxattr", TLINT, { TSTR, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[195] = { "llistxattr", TLINT, { TSTR, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[196] = { "flistxattr", TLINT, { TINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[197] = { "removexattr", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[198] = { "lremovexattr", TLINT, { TSTR, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[199] = { "fremovexattr", TLINT, { TINT, TSTR, TNONE, TNONE, TNONE, TNONE } },
	[200] = { "tkill", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[201] = { "time", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[202] = { "futex", TLINT, { TPTR, TINT, TUINT, TPTR, TPTR, TUINT } },
	[203] = { "sched_setaffinity", TLINT, { TINT, TUINT, TPTR, TNONE, TNONE, TNONE } },
	[204] = { "sched_getaffinity", TLINT, { TINT, TUINT, TPTR, TNONE, TNONE, TNONE } },
	[205] = { "set_thread_area", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[206] = { "io_setup", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[207] = { "io_destroy", TLINT, { TLUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[208] = { "io_getevents", TLINT, { TLUINT, TLINT, TLINT, TPTR, TPTR, TNONE } },
	[209] = { "io_submit", TLINT, { TLUINT, TLINT, TPTR, TNONE, TNONE, TNONE } },
	[210] = { "io_cancel", TLINT, { TLUINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[211] = { "get_thread_area", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[212] = { "lookup_dcookie", TLINT, { TLUINT, TWSCHAR, TLUINT, TNONE, TNONE, TNONE } },
	[213] = { "epoll_create", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[214] = { "epoll_ctl_old", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[215] = { "epoll_wait_old", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[216] = { "remap_file_pages", TLINT, { TLUINT, TLUINT, TLUINT, TLUINT, TLUINT, TNONE } },
	[217] = { "getdents64", TLINT, { TUINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[218] = { "set_tid_address", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[219] = { "restart_syscall", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[220] = { "semtimedop", TLINT, { TINT, TPTR, TUINT, TPTR, TNONE, TNONE } },
	[221] = { "fadvise64", TLINT, { TINT, TLINT, TLUINT, TINT, TNONE, TNONE } },
	[222] = { "timer_create", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[223] = { "timer_settime", TLINT, { TINT, TINT, TPTR, TPTR, TNONE, TNONE } },
	[224] = { "timer_gettime", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[225] = { "timer_getoverrun", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[226] = { "timer_delete", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[227] = { "clock_settime", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[228] = { "clock_gettime", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[229] = { "clock_getres", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[230] = { "clock_nanosleep", TLINT, { TINT, TINT, TPTR, TPTR, TNONE, TNONE } },
	[231] = { "exit_group", TNONE, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[232] = { "epoll_wait", TLINT, { TINT, TPTR, TINT, TINT, TNONE, TNONE } },
	[233] = { "epoll_ctl", TLINT, { TINT, TINT, TINT, TPTR, TNONE, TNONE } },
	[234] = { "tgkill", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[235] = { "utimes", TLINT, { TPTR, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[236] = { "vserver", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[237] = { "mbind", TLINT, { TLUINT, TLUINT, TLUINT, TPTR, TLUINT, TUINT } },
	[238] = { "set_mempolicy", TLINT, { TINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[239] = { "get_mempolicy", TLINT, { TPTR, TPTR, TLUINT, TLUINT, TLUINT, TNONE } },
	[240] = { "mq_open", TLINT, { TPTR, TINT, TUSHRT, TPTR, TNONE, TNONE } },
	[241] = { "mq_unlink", TLINT, { TPTR, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[242] = { "mq_timedsend", TLINT, { TINT, TSCHAR, TLUINT, TUINT, TPTR, TNONE } },
	[243] = { "mq_timedreceive", TLINT, { TINT, TWSCHAR, TLUINT, TPTR, TPTR, TNONE } },
	[244] = { "mq_notify", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[245] = { "mq_getsetattr", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[246] = { "kexec_load", TLINT, { TLUINT, TLUINT, TPTR, TLUINT, TNONE, TNONE } },
	[247] = { "waitid", TLINT, { TINT, TINT, TPTR, TINT, TPTR, TNONE } },
	[248] = { "add_key", TLINT, { TSTR, TSTR, TPTR, TLUINT, TINT, TNONE } },
	[249] = { "request_key", TLINT, { TSTR, TSTR, TSTR, TINT, TNONE, TNONE } },
	[250] = { "keyctl", TLINT, { TINT, TLUINT, TLUINT, TLUINT, TLUINT, TNONE } },
	[251] = { "ioprio_set", TLINT, { TINT, TINT, TINT, TNONE, TNONE, TNONE } },
	[252] = { "ioprio_get", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[253] = { "inotify_init", TLINT, { TNONE, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[254] = { "inotify_add_watch", TLINT, { TINT, TSTR, TUINT, TNONE, TNONE, TNONE } },
	[255] = { "inotify_rm_watch", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[256] = { "migrate_pages", TLINT, { TINT, TLUINT, TPTR, TPTR, TNONE, TNONE } },
	[257] = { "openat", TLINT, { TINT, TSTR, TINT, TUSHRT, TNONE, TNONE } },
	[258] = { "mkdirat", TLINT, { TINT, TSTR, TUSHRT, TNONE, TNONE, TNONE } },
	[259] = { "mknodat", TLINT, { TINT, TSTR, TUSHRT, TUINT, TNONE, TNONE } },
	[260] = { "fchownat", TLINT, { TINT, TSTR, TINT, TINT, TINT, TNONE } },
	[261] = { "futimesat", TLINT, { TINT, TSTR, TPTR, TNONE, TNONE, TNONE } },
	[262] = { "newfstatat", TLINT, { TINT, TSTR, TPTR, TINT, TNONE, TNONE } },
	[263] = { "unlinkat", TLINT, { TINT, TSTR, TINT, TNONE, TNONE, TNONE } },
	[264] = { "renameat", TLINT, { TINT, TSTR, TINT, TSTR, TNONE, TNONE } },
	[265] = { "linkat", TLINT, { TINT, TSTR, TINT, TSTR, TINT, TNONE } },
	[266] = { "symlinkat", TLINT, { TSTR, TINT, TSTR, TNONE, TNONE, TNONE } },
	[267] = { "readlinkat", TLINT, { TINT, TSTR, TWSCHAR, TINT, TNONE, TNONE } },
	[268] = { "fchmodat", TLINT, { TINT, TSTR, TUSHRT, TNONE, TNONE, TNONE } },
	[269] = { "faccessat", TLINT, { TINT, TSTR, TINT, TNONE, TNONE, TNONE } },
	[270] = { "pselect6", TLINT, { TINT, TPTR, TPTR, TPTR, TPTR, TPTR } },
	[271] = { "ppoll", TLINT, { TPTR, TUINT, TPTR, TPTR, TLUINT, TNONE } },
	[272] = { "unshare", TLINT, { TLUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[273] = { "set_robust_list", TLINT, { TPTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[274] = { "get_robust_list", TLINT, { TINT, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[275] = { "splice", TLINT, { TINT, TPTR, TINT, TPTR, TLUINT, TUINT } },
	[276] = { "tee", TLINT, { TINT, TINT, TLUINT, TUINT, TNONE, TNONE } },
	[277] = { "sync_file_range", TLINT, { TINT, TLINT, TLINT, TUINT, TNONE, TNONE } },
	[278] = { "vmsplice", TLINT, { TINT, TPTR, TLUINT, TUINT, TNONE, TNONE } },
	[279] = { "move_pages", TLINT, { TINT, TLUINT, TPTR, TPTR, TPTR, TINT } },
	[280] = { "utimensat", TLINT, { TINT, TSTR, TPTR, TINT, TNONE, TNONE } },
	[281] = { "epoll_pwait", TLINT, { TINT, TPTR, TINT, TINT, TPTR, TLUINT } },
	[282] = { "signalfd", TLINT, { TINT, TPTR, TLUINT, TNONE, TNONE, TNONE } },
	[283] = { "timerfd_create", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[284] = { "eventfd", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[285] = { "fallocate", TLINT, { TINT, TINT, TLINT, TLINT, TNONE, TNONE } },
	[286] = { "timerfd_settime", TLINT, { TINT, TINT, TPTR, TPTR, TNONE, TNONE } },
	[287] = { "timerfd_gettime", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[288] = { "accept4", TLINT, { TINT, TPTR, TPTR, TINT, TNONE, TNONE } },
	[289] = { "signalfd4", TLINT, { TINT, TPTR, TLUINT, TINT, TNONE, TNONE } },
	[290] = { "eventfd2", TLINT, { TUINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[291] = { "epoll_create1", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[292] = { "dup3", TLINT, { TUINT, TUINT, TINT, TNONE, TNONE, TNONE } },
	[293] = { "pipe2", TLINT, { TPTR, TINT, TNONE, TNONE, TNONE, TNONE } },
	[294] = { "inotify_init1", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[295] = { "preadv", TLINT, { TLUINT, TPTR, TLUINT, TLUINT, TLUINT, TNONE } },
	[296] = { "pwritev", TLINT, { TLUINT, TPTR, TLUINT, TLUINT, TLUINT, TNONE } },
	[297] = { "rt_tgsigqueueinfo", TLINT, { TINT, TINT, TINT, TPTR, TNONE, TNONE } },
	[298] = { "perf_event_open", TLINT, { TPTR, TINT, TINT, TINT, TLUINT, TNONE } },
	[299] = { "recvmmsg", TLINT, { TINT, TPTR, TUINT, TUINT, TPTR, TNONE } },
	[300] = { "fanotify_init", TLINT, { TUINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[301] = { "fanotify_mark", TLINT, { TINT, TUINT, TLUINT, TINT, TSTR, TNONE } },
	[302] = { "prlimit64", TLINT, { TINT, TUINT, TPTR, TPTR, TNONE, TNONE } },
	[303] = { "name_to_handle_at", TLINT, { TINT, TSTR, TPTR, TPTR, TINT, TNONE } },
	[304] = { "open_by_handle_at", TLINT, { TINT, TPTR, TINT, TNONE, TNONE, TNONE } },
	[305] = { "clock_adjtime", TLINT, { TINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[306] = { "syncfs", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[307] = { "sendmmsg", TLINT, { TINT, TPTR, TUINT, TUINT, TNONE, TNONE } },
	[308] = { "setns", TLINT, { TINT, TINT, TNONE, TNONE, TNONE, TNONE } },
	[309] = { "getcpu", TLINT, { TPTR, TPTR, TPTR, TNONE, TNONE, TNONE } },
	[310] = { "process_vm_readv", TLINT, { TINT, TPTR, TLUINT, TPTR, TLUINT, TLUINT } },
	[311] = { "process_vm_writev", TLINT, { TINT, TPTR, TLUINT, TPTR, TLUINT, TLUINT } },
	[312] = { "kcmp", TLINT, { TINT, TINT, TINT, TLUINT, TLUINT, TNONE } },
	[313] = { "finit_module", TLINT, { TINT, TSTR, TINT, TNONE, TNONE, TNONE } },
	[314] = { "sched_setattr", TLINT, { TINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[315] = { "sched_getattr", TLINT, { TINT, TPTR, TUINT, TUINT, TNONE, TNONE } },
	[316] = { "renameat2", TLINT, { TINT, TSTR, TINT, TSTR, TUINT, TNONE } },
	[317] = { "seccomp", TLINT, { TUINT, TUINT, TPTR, TNONE, TNONE, TNONE } },
	[318] = { "getrandom", TLINT, { TWSCHAR, TLUINT, TUINT, TNONE, TNONE, TNONE } },
	[319] = { "memfd_create", TLINT, { TSTR, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[320] = { "kexec_file_load", TLINT, { TINT, TINT, TLUINT, TPTR, TLUINT, TNONE } },
	[321] = { "bpf", TLINT, { TINT, TPTR, TUINT, TNONE, TNONE, TNONE } },
	[322] = { "execveat", TLINT, { TINT, TSTR, TPTR, TASTR, TINT, TNONE } },
	[323] = { "userfaultfd", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[324] = { "membarrier", TLINT, { TINT, TUINT, TINT, TNONE, TNONE, TNONE } },
	[325] = { "mlock2", TLINT, { TLUINT, TLUINT, TINT, TNONE, TNONE, TNONE } },
	[326] = { "copy_file_range", TLINT, { TINT, TPTR, TINT, TPTR, TLUINT, TUINT } },
	[327] = { "preadv2", TLINT, { TLUINT, TPTR, TLUINT, TLUINT, TLUINT, TINT } },
	[328] = { "pwritev2", TLINT, { TLUINT, TPTR, TLUINT, TLUINT, TLUINT, TINT } },
	[329] = { "pkey_mprotect", TLINT, { TPTR, TLUINT, TLUINT, TINT, TNONE, TNONE } },
	[330] = { "pkey_alloc", TLINT, { TLUINT, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[331] = { "pkey_free", TLINT, { TINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[332] = { "statx", TLINT, { TINT, TSTR, TUINT, TUINT, TPTR, TNONE } },
	[333] = { "io_pgetevents", TLINT, { TLUINT, TLINT, TLINT, TPTR, TPTR, TPTR } },
	[334] = { "rseq", TLINT, { TPTR, TUINT, TINT, TUINT, TNONE, TNONE } },
	[424] = { "pidfd_send_signal", TLINT, { TINT, TINT, TPTR, TUINT, TNONE, TNONE } },
	[425] = { "io_uring_setup", TLINT, { TUINT, TPTR, TNONE, TNONE, TNONE, TNONE } },
	[426] = { "io_uring_enter", TLINT, { TUINT, TUINT, TUINT, TUINT, TPTR, TLUINT } },
	[427] = { "io_uring_register", TLINT, { TUINT, TUINT, TPTR, TUINT, TNONE, TNONE } },
	[428] = { "open_tree", TLINT, { TINT, TSTR, TUINT, TNONE, TNONE, TNONE } },
	[429] = { "move_mount", TLINT, { TINT, TSTR, TINT, TSTR, TUINT, TNONE } },
	[430] = { "fsopen", TLINT, { TSTR, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[431] = { "fsconfig", TLINT, { TINT, TUINT, TSTR, TPTR, TINT, TNONE } },
	[432] = { "fsmount", TLINT, { TINT, TUINT, TUINT, TNONE, TNONE, TNONE } },
	[433] = { "fspick", TLINT, { TINT, TSTR, TUINT, TNONE, TNONE, TNONE } },
	[434] = { "pidfd_open", TLINT, { TINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[435] = { "clone3", TLINT, { TPTR, TLUINT, TNONE, TNONE, TNONE, TNONE } },
	[436] = { "close_range", TLINT, { TUINT, TUINT, TUINT, TNONE, TNONE, TNONE } },
	[437] = { "openat2", TLINT, { TINT, TSTR, TPTR, TLUINT, TNONE, TNONE } },
	[438] = { "pidfd_getfd", TLINT, { TINT, TINT, TUINT, TNONE, TNONE, TNONE } },
	[439] = { "faccessat2", TLINT, { TINT, TSTR, TINT, TINT, TNONE, TNONE } },
	[440] = { "process_madvise", TLINT, { TINT, TPTR, TLUINT, TINT, TUINT, TNONE } },
	[441] = { "epoll_pwait2", TLINT, { TINT, TPTR, TINT, TPTR, TPTR, TLUINT } },
	[442] = { "mount_setattr", TLINT, { TINT, TSTR, TUINT, TPTR, TLUINT, TNONE } },
	[443] = { "quotactl_fd", TLINT, { TUINT, TUINT, TUINT, TPTR, TNONE, TNONE } },
	[444] = { "landlock_create_ruleset", TLINT, { TPTR, TLUINT, TUINT, TNONE, TNONE, TNONE } },
	[445] = { "landlock_add_rule", TLINT, { TINT, TINT, TPTR, TUINT, TNONE, TNONE } },
	[446] = { "landlock_restrict_self", TLINT, { TINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[447] = { "memfd_secret", TLINT, { TUINT, TNONE, TNONE, TNONE, TNONE, TNONE } },
	[448] = { "process_mrelease", TLINT, { TINT, TUINT, TNONE, TNONE, TNONE, TNONE } },
	[449] = { "futex_waitv", TLINT, { TPTR, TUINT, TUINT, TPTR, TINT, TNONE } },
	[450] = { "set_mempolicy_home_node", TLINT, { TLUINT, TLUINT, TLUINT, TLUINT, TNONE, TNONE } },
	[451] = { "cachestat", TLINT, { TUINT, TPTR, TPTR, TUINT, TNONE, TNONE } },
};