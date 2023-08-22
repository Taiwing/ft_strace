#include "ft_strace.h"

const int	g_generic_si_code[] = {
	SI_USER, SI_KERNEL, SI_QUEUE, SI_TIMER, SI_MESGQ, SI_ASYNCIO, SI_TKILL
};

const char	*g_generic_si_code_names[] = {
	"SI_USER", "SI_KERNEL", "SI_QUEUE", "SI_TIMER", "SI_MESGQ", "SI_ASYNCIO",
	"SI_TKILL"
};

const int	g_sigill_si_code[] = {
	ILL_ILLOPC, ILL_ILLOPN, ILL_ILLADR, ILL_ILLTRP, ILL_PRVOPC, ILL_PRVREG,
	ILL_COPROC, ILL_BADSTK
};

const char	*g_sigill_si_code_names[] = {
	"ILL_ILLOPC", "ILL_ILLOPN", "ILL_ILLADR", "ILL_ILLTRP", "ILL_PRVOPC",
	"ILL_PRVREG", "ILL_COPROC", "ILL_BADSTK"
};

const int	g_sigfpe_si_code[] = {
	FPE_INTDIV, FPE_INTOVF, FPE_FLTDIV, FPE_FLTOVF, FPE_FLTUND, FPE_FLTRES,
	FPE_FLTINV, FPE_FLTSUB
};

const char	*g_sigfpe_si_code_names[] = {
	"FPE_INTDIV", "FPE_INTOVF", "FPE_FLTDIV", "FPE_FLTOVF", "FPE_FLTUND",
	"FPE_FLTRES", "FPE_FLTINV", "FPE_FLTSUB"
};

const int	g_sigsegv_si_code[] = {
	SEGV_MAPERR, SEGV_ACCERR, SEGV_BNDERR, SEGV_PKUERR
};

const char	*g_sigsegv_si_code_names[] = {
	"SEGV_MAPERR", "SEGV_ACCERR", "SEGV_BNDERR", "SEGV_PKUERR"
};

const int	g_sigbus_si_code[] = {
	BUS_ADRALN, BUS_ADRERR, BUS_OBJERR, BUS_MCEERR_AR, BUS_MCEERR_AO
};

const char	*g_sigbus_si_code_names[] = {
	"BUS_ADRALN", "BUS_ADRERR", "BUS_OBJERR", "BUS_MCEERR_AR", "BUS_MCEERR_AO"
};

const int	g_sigtrap_si_code[] = {
	TRAP_BRKPT, TRAP_TRACE
};

const char	*g_sigtrap_si_code_names[] = {
	"TRAP_BRKPT", "TRAP_TRACE"
};

const int	g_sigchld_si_code[] = {
	CLD_EXITED, CLD_KILLED, CLD_DUMPED, CLD_TRAPPED, CLD_STOPPED, CLD_CONTINUED
};

const char	*g_sigchld_si_code_names[] = {
	"CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "CLD_TRAPPED", "CLD_STOPPED",
	"CLD_CONTINUED"
};

const int	g_sigpoll_si_code[] = {
	POLL_IN, POLL_OUT, POLL_MSG, POLL_ERR, POLL_PRI, POLL_HUP
};

const char	*g_sigpoll_si_code_names[] = {
	"POLL_IN", "POLL_OUT", "POLL_MSG", "POLL_ERR", "POLL_PRI", "POLL_HUP"
};

const t_si_code_names	g_si_code_names[SI_CODE_NAMES_SIZE] = {
	[0] = {g_generic_si_code, g_generic_si_code_names, 7},
	[SIGILL] = {g_sigill_si_code, g_sigill_si_code_names, 8},
	[SIGFPE] = {g_sigfpe_si_code, g_sigfpe_si_code_names, 8},
	[SIGSEGV] = {g_sigsegv_si_code, g_sigsegv_si_code_names, 4},
	[SIGBUS] = {g_sigbus_si_code, g_sigbus_si_code_names, 5},
	[SIGTRAP] = {g_sigtrap_si_code, g_sigtrap_si_code_names, 2},
	[SIGCHLD] = {g_sigchld_si_code, g_sigchld_si_code_names, 6},
	[SIGPOLL] = {g_sigpoll_si_code, g_sigpoll_si_code_names, 6},
};
