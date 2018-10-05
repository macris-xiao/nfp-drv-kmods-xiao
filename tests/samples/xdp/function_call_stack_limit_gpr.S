.include "xdp.S"

;_ Use 64 * 7 + 128 = 576 bytes of stack.
;_ Value 64 accounts for 60 bytes used by subprogram, plus 4 bytes for saving
;_ the return address (rounded up, with no effect, to 64).
;_ Value 128 accounts for 60 bytes used by foo7, plus space for saving return
;_ address, and space for saving callee-saved registers; then the total is
;_ rounded up to the above multiple of 64 bytes.
;_ Final amout is above 512, so this program should be rejected for XDP offload
;_ (but accepted for host XDP, which does not need to account for space needed
;_ by callee-saved registers and return addresses).

xdp_prog1:
	r1 = 0
	*(u8 *)(r10 - 60) = r1
	call foo1
	exit

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
	r6 = 1
	*(u8 *)(r10 - 60) = r6
	r0 = XDP_PASS
	exit
