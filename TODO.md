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

- Maybe use the function definitions of the syscalls if they exist, not just the
  SYSCALL\_DEFINE or prototype. This would probably be better than the prototype
  technique. We might find more missing syscalls and this would avoid the
  anonymous parameters problem. Might kill two birds with one stone.
  - see how I can fix the missing parameter names, this is quite annoying
  - try and fix the missing syscalls
- do an auto-updating page from the script as a side project, could be cool :D
- cleanup the script a little bit (move the always executing sections to the
  same place, maybe refactor what can be refactored)
- add options, like an option to add a 'fake' name to the anonymous parameters

- possibly handle other architectures that only rely on the generic syscall
  table defined in include/uapi/asm-generic/unistd.h, if I understand correctly
  this might apply to every sub directory under the arch/ directory that does
  not contain a specific syscall ".tbl" file (maybe create a custom generic
  .tbl" file from the header and use it instead of a specific one)
- eventually add test to check if rg exists on the machine (and other deps)
- write usage functions for both scripts

-- find syscalls --

--- MAYBE ---

- remove mallocs in the command building function so that we dont need
  dynamic momory allocation anywhere
