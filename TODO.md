--- TODO ---

--- MAYBE ---

- Remove pid\_table if it is proved to be useless (which it very well migth be).
  Simply parse the string and PTRACE\_SEIZE processes along the way if it is
  indeed useless. Probably just keep a process\_counter.
