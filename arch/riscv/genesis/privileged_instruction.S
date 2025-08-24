#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>

/* TODO: Map .text.privinst section as user-mode page */
.section ".text.privinst"

SYM_FUNC_START(_genesis_write_satp)
	csrw CSR_SATP, a0
	ret
SYM_FUNC_END(_genesis_write_satp)

// FIXME: MSB (63rd bit) is set after executing csrw and csrs
SYM_FUNC_START(_genesis_write_csr)
	csrw CSR_STATUS, a0
	ret
SYM_FUNC_END(_genesis_write_csr)

SYM_FUNC_START(_genesis_set_csr)
	csrs CSR_STATUS, a0
	ret
SYM_FUNC_END(_genesis_set_csr)

SYM_FUNC_START(_genesis_write_tvec)
	csrw CSR_TVEC, a0
	ret
SYM_FUNC_END(_genesis_write_tvec)
