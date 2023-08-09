#pragma once

#include <stdint.h>

/*
** Syscall
*/
typedef struct	s_syscall
{
	int			nargs;
	char		*name;
}				t_syscall;

// Syscall tables
extern t_syscall		g_syscall_32[];
extern t_syscall		g_syscall_64[];

// Syscall limits
#define SYSCALL_ARG_MAX	6
#define SYSCALL_32_MAX	sizeof(g_syscall_32) / sizeof(t_syscall)
#define SYSCALL_64_MAX	sizeof(g_syscall_64) / sizeof(t_syscall)

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

/*
** Register union for 32/64-bit processes
*/
typedef union	u_user_regs
{
	t_user_regs_32	regs32;
	t_user_regs_64	regs64;
}				t_user_regs;
