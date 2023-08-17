#pragma once

#include <stdint.h>

/*
** Syscall parameter types
*/
enum	e_syscall_type {
	TNONE = 0,	// no parameter
	TUSHRT,		// unsigned short
	TINT,		// int
	TUINT,		// unsigned int
	TLINT,		// long
	TLUINT,		// unsigned long
	TPTR,		// address
	TSTR,		// regular string
	TASTR,		// string array
	TSCHAR,		// sized char buffer (size is in the next param)
	TWSCHAR,	// hanging sized char buffer (size is the positive return value)
	TWSTR,		// hanging string
};

// Macro to check if the parameter needs to be waited for
#define IS_WAIT_TYPE(x) (x == TWSCHAR || x == TWSTR)

// Syscall limits
#define G_SYSCALL_X86_64 452
#define G_SYSCALL_X86_I386 452
#define SYSCALL_MAX_PARAMETERS 6

/*
** Syscall
*/
typedef struct			s_syscall
{
	char				*name;
	enum e_syscall_type	return_type;
	enum e_syscall_type	parameter_type[SYSCALL_MAX_PARAMETERS];
}						t_syscall;

/*
** Syscall tables
*/
extern const t_syscall	g_syscall_x86_64[G_SYSCALL_X86_64];
extern const t_syscall	g_syscall_x86_i386[G_SYSCALL_X86_I386];

/*
** Register structure for 32-bit processes
*/
typedef struct	s_user_regs_32
{
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
}				t_user_regs_32;

// Macro to get 32-bit registers from parameter index
#define REGS_32_ARRAY(regs, index) (\
	index == 0 ? regs->ebx : \
	index == 1 ? regs->ecx : \
	index == 2 ? regs->edx : \
	index == 3 ? regs->esi : \
	index == 4 ? regs->edi : \
	index == 5 ? regs->ebp : 0\
)

/*
** Register structure for 64-bit processes
*/
typedef struct	s_user_regs_64
{
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t orig_rax;
	uint64_t rip;
	uint64_t cs;
	uint64_t eflags;
	uint64_t rsp;
	uint64_t ss;
	uint64_t fs_base;
	uint64_t gs_base;
	uint64_t ds;
	uint64_t es;
	uint64_t fs;
	uint64_t gs;
}				t_user_regs_64;

// Macro to get 64-bit registers from parameter index
#define REGS_64_ARRAY(regs, index) (\
	index == 0 ? regs->rdi : \
	index == 1 ? regs->rsi : \
	index == 2 ? regs->rdx : \
	index == 3 ? regs->r10 : \
	index == 4 ? regs->r8 : \
	index == 5 ? regs->r9 : 0\
)

/*
** Register union for 32/64-bit processes
*/
typedef union	u_user_regs
{
	t_user_regs_32	regs32;
	t_user_regs_64	regs64;
}				t_user_regs;
