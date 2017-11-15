# Test the last insn is an jump instruction

	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 60
	if r3 > r2 goto LBB0_2
	# Compare with 0x1FFFF must need extra instructions to
        # build the constant, related code path could be tested.
	if r0 < 0x1FFFF goto LLAST_0
LBB0_2:
	exit
LLAST_0:
	r2 = 13330
	*(u16 *)(r1 + 12) = r2
	# Swap source and destination address
	r2 = *(u32 *)(r1 + 0)
	r3 = *(u32 *)(r1 + 6)
	*(u32 *)(r1 + 0) = r3
	*(u32 *)(r1 + 6) = r2
	r2 = *(u16 *)(r1 + 4)
	r3 = *(u16 *)(r1 + 10)
	*(u16 *)(r1 + 4) = r3
	*(u16 *)(r1 + 10) = r2
	r0 = 3
	# The last instruction is an jump.
	goto LBB0_2
