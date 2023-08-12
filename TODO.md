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
  files (\*.tbl, \*.h and \*.c files), get the syscall number, the syscall name,
  the parameter count, the parameter types and the entry vector function (if
  this is good, maybe do an auto-updating page as a side project, could be cool
  :D), do that both for x86\_64 and for i386 (64bit and 32bit) (also add
  return type now that I see that its not always int, it can be a pointer in
  case of mmap)
- write an other script to generalize this process, meaning automatically get
  the syscall info for each possible arch/abi pair from the linux source
- possibly handle other architectures that only rely on the generic syscall
  table defined in include/uapi/asm-generic/unistd.h, if I understand correctly
  this might apply to every sub directory under the arch/ directory that does
  not contain a specific syscall ".tbl" file (maybe create a custom generic
  .tbl" file from the header and use it instead of a specific one)
- see how to handle the compat_* stuff (a lot of syscalls are actually missing
  because only one of syscall entry or compat is given (the other is "-"), do we
  add it to the collected data ? do we ignore it if the normal entry is given ?
  if there is only the compat, what to do ? use it to replace the entry ? But
  really, what does this fucking "-" symbol mean ? Is it just like empty but to
  be able to have only the compat column filled ? Probably, but why do this ?
  why not use the regular entry point column instead if there is only one ? Is
  this because the syscall should not work under normal circumstances ? so many
  questions... (see linux/arch/s390/kernel/syscalls/syscall.tbl for an example
  of this)

  - create a shell function to parse the sys\_xxx function declaration and get
    the return type, the parameter count and the parameter types
  - create shell functions to parse SYSCALL\_DEFINE and get the same info (but
    without the return type that will be set to long by default)
  - handle non implemented syscalls (still add them to the final list but with
    0 parameter)
  - show big fat errors for syscalls that do not have a final unique prototype
  - add special cases when needed (they should be few, like clone)

  - eventually add test to check if rg exists on the machine, fallback on grep
    otherwise (the queries will have to change a little bit for that)

-- find syscalls --

--- MAYBE ---

- remove mallocs in the command building function so that we dont need
  dynamic momory allocation anywhere
