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
  -- ok to fix this, I should not check the syscall number again on exit tracing
  -- because we already know it (just save the first getregset result and use
  -- this as a reference if needed, just get the result)
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
- handle ERESTARTSYS ERESTARTNOINTR and ERESTARTNOHAND (show '?' as a return
  value and print the ERESTART* value after it like the original). It happens
  when a syscall is interrupted by a signal and SA\_RESTART flag is set (the
  syscall restarts).

-- find syscalls --

- write a script to gather syscall info automatically based on the linux source
  files (.tbl files and syscalls.h maybe), get the syscall number, the syscall
  name, the parameter count, the parameter types and the entry vector function
  (if this is good, maybe do an auto-updating page as a side project, could be
  cool :D), do that both for x86\_64 and for i386 (64bit and 32bit) (also add
  return type now that I see that its not always int, it can be a pointer in
  case of mmap)

  - in case of multiple SYSCALL\_DEFINE matches try and find the file for the
    right architecture that has only one match
  - if it does not work look for the "entry vector" (meaning the sys\_xxx
    function declaration) in a header (try and get one match too, like for the
	defines)
  - create shell functions to parse SYSCALL\_DEFINE and get the parameter count
    and each parameter type and name
  - create an other one to parse the sys\_xxx function declaration and get the
    same info
  - handle non implemented syscalls (still add them to the final list but with
    0 parameter)
  - show big fat errors for syscalls that do not have a final unique prototype

-- find syscalls --

--- MAYBE ---

- remove mallocs in the command building function so that we dont need
  dynamic momory allocation anywhere
