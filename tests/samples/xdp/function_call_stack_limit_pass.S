.include "xdp.S"

// Use 64 * 8 = 512 bytes of stack.
// Value 64 accounts for 60 bytes used by subprogram, plus 4 bytes for saving
// the return address (rounded up to 64, without any effect save for main).
// We would need more bytes if we were to save callee-saved registers for each
// callee frame. However, we only do this when subprograms clobber those
// registers, which is not the case for any subprogram here. Therefore this
// program should be accepted for offload.

xdp_prog1:
	r1 = 0
	*(u8 *)(r10 - 60) = r1
	call foo1
	exit

/* CHECK-CODEGEN-TIMES-7: .*rtn\[gprA_\d\].* */

foo1:
	*(u8 *)(r10 - 60) = r1
	call foo2
	exit

foo2:
	*(u8 *)(r10 - 60) = r1
	call foo3
	exit

foo3:
	*(u8 *)(r10 - 60) = r1
	call foo4
	exit

foo4:
	*(u8 *)(r10 - 60) = r1
	call foo5
	exit

foo5:
	*(u8 *)(r10 - 60) = r1
	call foo6
	exit

foo6:
	*(u8 *)(r10 - 60) = r1
	call foo7
	exit

foo7:
	*(u8 *)(r10 - 60) = r1
	r0 = XDP_PASS
	exit
