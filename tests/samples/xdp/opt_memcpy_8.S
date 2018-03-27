// Test memory copy on:
//
//   cross memory access on same base registers.
//   cross memory access on different base registers.

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// There should not be any such transfer move as all of the sequences
	// below are cross reference.
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_2, \-\-, B, \$xfer_2\] */

	r2 = *(u32 *)(r1 + 64)
	*(u32 *)(r1 + 60) = r2
	r2 = *(u32 *)(r1 + 60)
	*(u32 *)(r1 + 56) = r2
	r2 = *(u32 *)(r1 + 56)
	*(u32 *)(r1 + 52) = r2

	r4 = r1
	r2 = *(u32 *)(r1 + 64)
	*(u32 *)(r4 + 60) = r2
	r2 = *(u32 *)(r1 + 60)
	*(u32 *)(r4 + 56) = r2
	r2 = *(u32 *)(r1 + 56)
	*(u32 *)(r4 + 52) = r2

	r5 = r1
	r2 = *(u32 *)(r5 + 64)
	*(u32 *)(r4 + 60) = r2
	r2 = *(u32 *)(r5 + 60)
	*(u32 *)(r4 + 56) = r2
	r2 = *(u32 *)(r5 + 56)
	*(u32 *)(r4 + 52) = r2

	r4 += 60
	r2 = *(u32 *)(r1 + 64)
	*(u32 *)(r4 + 0) = r2
	r2 = *(u32 *)(r1 + 60)
	*(u32 *)(r4 - 4) = r2
	r2 = *(u32 *)(r1 + 56)
	*(u32 *)(r4 - 8) = r2

	r5 += 64
	r2 = *(u32 *)(r5 + 0)
	*(u32 *)(r4 + 0) = r2
	r2 = *(u32 *)(r5 - 4)
	*(u32 *)(r4 - 4) = r2
	r2 = *(u32 *)(r5 - 8)
	*(u32 *)(r4 - 8) = r2

	r4 -= 20
	r2 = *(u32 *)(r1 + 64)
	*(u32 *)(r4 + 20) = r2
	r2 = *(u32 *)(r1 + 60)
	*(u32 *)(r4 + 16) = r2
	r2 = *(u32 *)(r1 + 56)
	*(u32 *)(r4 + 12) = r2

	PREPARE_PACKET_FOOTER
