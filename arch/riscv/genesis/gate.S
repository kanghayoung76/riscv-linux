#include <linux/linkage.h>
//#include <asm-generic/exDport.h>
#include <linux/export.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>

/* GENESIS Entry Gate
 * The 't6' register is caller-saved register.
 */

SYM_FUNC_START(_genesis_uaccess_entry)
SYM_FUNC_START(_genesis_entry)
	csrr t6, CSR_STATUS	// Read CSR
	addi sp, sp, -(2*SZREG)	// Adjust the stack pointer
	REG_S t6, (sp)		// Save CSR
	REG_S ra, SZREG(sp)	// Save the return address
	csrc CSR_STATUS, SR_IE	// Turn off interrupt
	li t6, SR_SUM		// Load SUM immediate value
	csrs CSR_STATUS, t6	// Set the SUM bit (Disable SUM)
	call inner_handler	// Jump to the inner domain
SYM_FUNC_END(_genesis_entry)
SYM_FUNC_END(_genesis_uaccess_entry)
EXPORT_SYMBOL(_genesis_entry)
EXPORT_SYMBOL(_genesis_uaccess_entry)

/* GENESIS Exit Gate */
SYM_FUNC_START(_genesis_exit)
	li t6, SR_SUM		// Load SUM Immediate value (18th)
	csrc CSR_STATUS, t6	// Clear the SUM bit (Re-enable SUM)
	REG_L t6, (sp)		// Load the saved CSR
	REG_L ra, SZREG(sp)	// Load the return address
	addi sp, sp, (2*SZREG)	// Adjust the stack pointer
	andi t6, t6, SR_IE	// Bitwise-and to get the IE bit
	beqz t6, _to_ret	// Check if the IE was set
	csrs CSR_STATUS, SR_IE	// If set, restore the IE bit
_to_ret:
        ret			// Return to the outer kernel
SYM_FUNC_END(_genesis_exit)
