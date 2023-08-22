############################## COMPILE VAR #####################################

CC			=	gcc
#CFLAGS		=	-Wall -Wextra -Werror
CFLAGS		=	-Wall -Wextra -Werror -g -fsanitize=address,undefined
HDIR		=	includes
SRCDIR		=	src
HFLAGS		=	-I $(HDIR)
NAME		=	ft_strace

############################## SOURCES #########################################

PRINTDIR		=	print
SYSCALLDIR		=	syscall

SRCC			=	main.c\
					pid.c\
					execute_command.c\
					wait.c\
					find_command.c\
					signals.c\
					options.c\

PRINTC			=	summary.c\
					utils.c\
					signal.c\
					count.c\
					syscall_32.c\
					parameters.c\
					si_code.c\
					syscall_64.c\
					ts.c\

SYSCALLC		=	x86_i386.c\
					x86_64.c\
					status.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(PRINTC))\
					$(patsubst %.c,%.o,$(SYSCALLC))\
					$(patsubst %.c,%.o,$(SRCC))\

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.c	$(SRCDIR)/$(PRINTDIR)
vpath			%.c	$(SRCDIR)/$(SYSCALLDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ))

main.o: ft_strace.h syscall.h
pid.o: ft_strace.h syscall.h
execute_command.o: ft_strace.h syscall.h
wait.o: ft_strace.h syscall.h
summary.o: ft_strace.h syscall.h
utils.o: ft_strace.h syscall.h
signal.o: ft_strace.h syscall.h
count.o: ft_strace.h syscall.h
syscall_32.o: ft_strace.h syscall.h
parameters.o: ft_strace.h syscall.h
si_code.o: ft_strace.h syscall.h
syscall_64.o: ft_strace.h syscall.h
ts.o: ft_strace.h syscall.h
find_command.o: ft_strace.h syscall.h
signals.o: ft_strace.h syscall.h
options.o: ft_strace.h syscall.h
x86_i386.o: syscall.h
x86_64.o: syscall.h
status.o: ft_strace.h syscall.h
%.o: %.c
	@mkdir -p $(ODIR)
	$(CC) -c $(CFLAGS) $< $(HFLAGS) -o $(ODIR)/$@

$(ODIR):
	mkdir -p $@

############################## CLEANUP #########################################

clean:
	rm -rf $(ODIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
