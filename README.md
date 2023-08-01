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
