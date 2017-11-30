// Test memory copy on:
//
//   jump to load in the middle of a sequence.
//   jump to store in the middle of a sequence.

	.include "opt_memcpy_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER


	// jump to load
	if r2 > r1 goto LTEST_1
	// jump to store
	if r2 > r3 goto LTEST_2

	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, 0x880\] */
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x14,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x14,.*\], ctx_swap */
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_8, \-\-, B, \$xfer_8\] */
	/* CHECK-CODEGEN: .*alu\[\$xfer_2, \-\-, B, \$xfer_2\] */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x10,.*\], ctx_swap */
	r2 = *(u32 *)(r1 + 20)
	*(u32 *)(r1 + 16) = r2
	r2 = *(u32 *)(r1 + 24)
	*(u32 *)(r1 + 20) = r2
	r2 = *(u32 *)(r1 + 28)
	*(u32 *)(r1 + 24) = r2
LTEST_1:
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x20,.*\], ctx_swap */
	/* CHECK-CODEGEN: .*alu\[\$xfer_3, \-\-, B, \$xfer_3\] */
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_5, \-\-, B, \$xfer_5\] */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x1c,.*\], ctx_swap */
	r2 = *(u32 *)(r1 + 32)
	*(u32 *)(r1 + 28) = r2
	r2 = *(u32 *)(r1 + 36)
	*(u32 *)(r1 + 32) = r2
	r2 = *(u32 *)(r1 + 40)
	*(u32 *)(r1 + 36) = r2
	r2 = *(u32 *)(r1 + 44)
	*(u32 *)(r1 + 40) = r2
	r2 = *(u32 *)(r1 + 48)
LTEST_2:
	*(u32 *)(r1 + 44) = r2
	r2 = *(u32 *)(r1 + 52)
	*(u32 *)(r1 + 48) = r2

	PREPARE_PACKET_FOOTER
