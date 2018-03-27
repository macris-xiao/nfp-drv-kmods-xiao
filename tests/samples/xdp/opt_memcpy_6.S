// Test memory copy on:
//
//   copy length <= 32-bytes.
//   copy length is 4-byte aligned.
//   multiple sequences, all valid.
//   copy elem wideth is double-word.

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// double-word copy sequence (24-bytes)
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x18,.*\], ctx_swap */
	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, 0x1780\] */
	/* CHECK-CODEGEN-NOT: .*mem\[write8_swap,.*0x10,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x10,.*\], ctx_swap */
	r2 = *(u64 *)(r1 + 24)
	*(u64 *)(r1 + 16) = r2
	r2 = *(u64 *)(r1 + 32)
	*(u64 *)(r1 + 24) = r2
	r2 = *(u64 *)(r1 + 40)
	*(u64 *)(r1 + 32) = r2

	// another sequence (16-bytes)
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_6, \-\-, B, \$xfer_6\] */
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x38,.*\], ctx_swap */
	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, 0xf80\] */
	/* CHECK-CODEGEN-NOT: .*mem\[write8_swap,.*0x28,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x28,.*\], ctx_swap */
	r2 = *(u64 *)(r1 + 64)
	*(u64 *)(r1 + 48) = r2
	r2 = *(u64 *)(r1 + 56)
	*(u64 *)(r1 + 40) = r2

	PREPARE_PACKET_FOOTER
