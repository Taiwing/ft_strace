--- TODO ---

- handle ft\_strace's signals (probably ignore most of them or redirect to
  child process(es))

--- MAYBE ---

- Remove pid\_table if it proved to be useless (which it very well migth be).
  Simply parse the string and PTRACE\_SEIZE processes along the way if it is
  indeed useless. Probably just keep a process\_counter.
