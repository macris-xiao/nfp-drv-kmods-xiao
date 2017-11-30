// Test memory copy on:
//
//   copy length <= 8.
//   copy elem width is byte.

	.include "opt_memcpy_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// sequence ascending order (8-bytes)
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x48,.*\], ctx_swap */
	/* CHECK-CODEGEN: .*alu\[\$xfer_1, \-\-, B, \$xfer_1\] */
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_2, \-\-, B, \$xfer_2\] */
	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, .*\] */
	/* CHECK-CODEGEN: .*mem\[write8_swap,.*0x27,.*\], ctx_swap */
	r2 = *(u8 *)(r1 + 72)
	*(u8 *)(r1 + 39) = r2
	r2 = *(u8 *)(r1 + 73)
	*(u8 *)(r1 + 40) = r2
	r2 = *(u8 *)(r1 + 74)
	*(u8 *)(r1 + 41) = r2
	r2 = *(u8 *)(r1 + 75)
	*(u8 *)(r1 + 42) = r2
	r2 = *(u8 *)(r1 + 76)
	*(u8 *)(r1 + 43) = r2
	r2 = *(u8 *)(r1 + 77)
	*(u8 *)(r1 + 44) = r2
	r2 = *(u8 *)(r1 + 78)
	*(u8 *)(r1 + 45) = r2
	r2 = *(u8 *)(r1 + 79)
	*(u8 *)(r1 + 46) = r2

	PREPARE_PACKET_FOOTER
