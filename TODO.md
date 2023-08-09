--- TODO ---

- print each syscall only once (print provided arguments and add a special
  case for read and maybe others, and wait for the return before printing it)
- also handle cases where a syscall is unfinished with the "<unfinished...>"
  thing (I think, actually look that shit up)
- create a structure for traced processes storing the pid and other info
  like the state, if it is a 32bit or a 64bit process, the last/current
  syscall, and probably more...
- see why rt\_sigreturn() always turns into an unknown\_syscall on syscall
  exit (probably has something to do with its name lol) and fix it
- write a script to gather syscall info automatically based on the linux source
  files (.tbl files and syscalls.h maybe), get the syscall number, the syscall
  name, the parameter count and the parameter types (if this is good, maybe do
  an auto-updating page as a side project, could be cool :D), do that both for
  x86\_64 and for i386 (64bit and 32bit)
- rework the syscall structure so that it includes a list of argument types (but
  simplified to not get crazy on printing, like a generic address type for
  non-char pointers, int, uint, etc...)
- maybe add a 'flag' for arguments that have to be waited for (meaning that the
  value will be set on syscall exit like for the read buffer content), this
  would only really make sense for printable addresses like strings (or char
  buffers in general). This would be cool to generalize the waiting process
  (not just create ugly special cases for read and read like syscalls)
- check that the syscall parameters are read from the right registers
  (especially in 64bit, where there seems to be two different register schemes,
  a "kernel" and a "user" one, look that shit up to make sure this is good)

--- MAYBE ---

- remove mallocs in the command building function so that we dont need
  dynamic momory allocation anywhere
