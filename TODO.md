--- TODO ---

- also 'add <syscall> resumed... thing'
- see what's going on the the restart\_syscall thing
- handle ERESTARTSYS ERESTARTNOINTR and ERESTARTNOHAND (show '?' as a return
  value and print the ERESTART* value after it like the original). It happens
  when a syscall is interrupted by a signal and SA\_RESTART flag is set (the
  syscall restarts). More generally, handle errno values for failing syscalls
  (depending on the return type I guess...)
- implement the other options/bonuses
- cleanup the events.c code a little bit and add some comments to clarify all
  this because this is not very very clear as is (also clean main... and the
  entire code base why not?)
- test the shit out of this ft\_strace (make sure every edge case is handled)
- remove cfg parameter wherever it is since it is a global variable now

-- find syscalls --

- see how I can fix the missing parameter names, this is quite annoying
- try and fix the missing syscalls
- do an auto-updating page from the script as a side project, could be cool :D
- cleanup the script a little bit (move the always executing sections to the
  same place, maybe refactor what can be refactored)
- add options, like an option to add a 'fake' name to the anonymous parameters

- MAYBE completely refactor the script: Do this the other way around, meaning
  first get every syscall definition, prototype, etc... parse them and store
  them in a big array/dictionnary. Add more info to it, like the filename and
  the line of the match. Then parse every syscall table as usual and simply look
  in the array for the given match. This array would store every match for every
  syscall, regardless of the number of matches for any individual syscall. The
  priority rules would have to be applied when looking for a specific syscall
  from the tables. If there are multiple matches, like for the clone functions,
  simply use the filename and Kconfig as usual to preprocess the file with gcc.
  Use an other language of course for storing and using the array, this will be
  way easier than in bash (if it is not actually impossible to do ^^). This
  should also be way faster as most of the work would be done once instead of
  doing it for each arch/abi pair. Also, we can know in advance where the
  parameter names are missing and do some work there to fix it (like using other
  declarations with the same prototype).

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
