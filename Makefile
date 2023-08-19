############################## COMPILE VAR #####################################

CC			=	gcc
#CFLAGS		=	-Wall -Wextra -Werror
CFLAGS		=	-Wall -Wextra -Werror -g -fsanitize=address,undefined
HDIR		=	includes
SRCDIR		=	src
HFLAGS		=	-I $(HDIR)
NAME		=	ft_strace

############################## SOURCES #########################################

SRCC			=	syscall.c\
					main.c\
					print.c\
					syscall_table_x86_64.c\
					syscall_table_x86_i386.c\
					pid.c\
					events.c\
					execute_command.c\
					print_syscall_64.c\
					find_command.c\
					print_syscall_32.c\
					signals.c\
					options.c\
					print_parameters.c\

ODIR			=	obj
OBJ				=	$(patsubst %.c,%.o,$(SRCC))

vpath			%.o	$(ODIR)
vpath			%.h	$(HDIR)
vpath			%.c	$(SRCDIR)

############################## BUILD ###########################################

all: $(NAME)

$(NAME): $(ODIR) $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(patsubst %.o,$(ODIR)/%.o,$(OBJ))

syscall.o: ft_strace.h syscall.h
main.o: ft_strace.h syscall.h
print.o: ft_strace.h syscall.h
syscall_table_x86_64.o: syscall.h
syscall_table_x86_i386.o: syscall.h
pid.o: ft_strace.h syscall.h
events.o: ft_strace.h syscall.h
execute_command.o: ft_strace.h syscall.h
print_syscall_64.o: ft_strace.h syscall.h
find_command.o: ft_strace.h syscall.h
print_syscall_32.o: ft_strace.h syscall.h
signals.o: ft_strace.h syscall.h
options.o: ft_strace.h syscall.h
print_parameters.o: ft_strace.h syscall.h
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
