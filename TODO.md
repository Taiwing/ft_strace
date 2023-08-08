--- TODO ---

- create a structure for traced processes storing the pid and other info
  like the state, if it is a 32bit or a 64bit process, the last/current
  syscall, and probably more...

--- MAYBE ---

- remove mallocs in the command building function so that we dont need
  dynamic momory allocation anywhere
