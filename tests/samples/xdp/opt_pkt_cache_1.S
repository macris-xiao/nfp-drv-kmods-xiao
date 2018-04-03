// Test packet cache for aligned offsets
/* CHECK-CODEGEN-TIMES-5: .*mem\[read32_swap,.*\], ctx_swap */

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER
	// sequence with increasing offsets
	r2 = *(u8 *)(r1 + 14)
	r3 = *(u16 *)(r1 + 18)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x12,.*\], ctx_swap */
	r4 = *(u32 *)(r1 + 22)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x16,.*\], ctx_swap */
	r5 = *(u64 *)(r1 + 26)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x1a,.*\], ctx_swap */
	*(u8 *)(r1 + 34) = r2
	*(u16 *)(r1 + 35) = r3
	*(u32 *)(r1 + 37) = r4
	*(u64 *)(r1 + 41) = r5

	// sequence with the same offset
	r2 = *(u8 *)(r1 + 14)
	r3 = *(u16 *)(r1 + 14)
	r4 = *(u32 *)(r1 + 14)
	r5 = *(u64 *)(r1 + 14)
	*(u8 *)(r1 + 49) = r2
	*(u16 *)(r1 + 50) = r3
	*(u32 *)(r1 + 52) = r4
	*(u64 *)(r1 + 56) = r5

	PREPARE_PACKET_FOOTER
