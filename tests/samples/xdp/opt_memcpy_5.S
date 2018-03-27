// Test memory copy on:
//
//   copy length > 32-bytes.
//   copy length is 4-byte aligned.
//   multiple sequences, one with cross mem access.
//   copy elem width is word.

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// sequence aescending (36-bytes)
	/* CHECK-CODEGEN: .*immed\[\-\-, 0x880\] */
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x14,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*alu\[\$xfer_8, \-\-, B, \$xfer_8\] */
	/* CHECK-CODEGEN: .*immed\[\-\-, 0x880\] */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x10,.*\], indirect_ref */
	r2 = *(u32 *)(r1 + 20)
	*(u32 *)(r1 + 16) = r2
	r2 = *(u32 *)(r1 + 24)
	*(u32 *)(r1 + 20) = r2
	r2 = *(u32 *)(r1 + 28)
	*(u32 *)(r1 + 24) = r2
	r2 = *(u32 *)(r1 + 32)
	*(u32 *)(r1 + 28) = r2
	r2 = *(u32 *)(r1 + 36)
	*(u32 *)(r1 + 32) = r2
	r2 = *(u32 *)(r1 + 40)
	*(u32 *)(r1 + 36) = r2
	r2 = *(u32 *)(r1 + 44)
	*(u32 *)(r1 + 40) = r2
	r2 = *(u32 *)(r1 + 48)
	*(u32 *)(r1 + 44) = r2
	r2 = *(u32 *)(r1 + 52)
	*(u32 *)(r1 + 48) = r2
	// another sequence descending with overriding logic
	/* CHECK-CODEGEN-NOT: .*mem\[write8_swap,.*\], indirect_ref */
	/* CHECK-CODEGEN-NOT: .*mem\[write32_swap,.*\], ctx_swap */
	r2 = *(u32 *)(r1 + 64)
	*(u32 *)(r1 + 60) = r2
	r2 = *(u32 *)(r1 + 60)
	*(u32 *)(r1 + 56) = r2
	r2 = *(u32 *)(r1 + 56)
	*(u32 *)(r1 + 52) = r2

	PREPARE_PACKET_FOOTER
