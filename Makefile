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
					pid.c\
					events.c\
					execute_command.c\
					find_command.c\
					options.c\

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
main.o: ft_strace.h
print.o: ft_strace.h
pid.o: ft_strace.h
events.o: ft_strace.h
execute_command.o: ft_strace.h
find_command.o: ft_strace.h
options.o: ft_strace.h
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
