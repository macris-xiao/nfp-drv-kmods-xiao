// Test packet cache for long range which needs indirect ref
/* CHECK-CODEGEN-TIMES-3: .*mem\[read32_swap,.*\], ctx_swap */

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	r2 = *(u8 *)(r1 + 14)
	/* CHECK-CODEGEN-TIMES-1: .*mem\[read32_swap,.*0xe,.*\], indirect_ref, ctx_swap */
	r3 = *(u16 *)(r1 + 40)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x28,.*\], ctx_swap */
	r4 = *(u32 *)(r1 + 43)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x2b,.*\], ctx_swap */
	r5 = *(u64 *)(r1 + 48)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x30,.*\], ctx_swap */
	*(u8 *)(r1 + 60) = r2
	*(u16 *)(r1 + 61) = r3
	*(u32 *)(r1 + 63) = r4
	*(u64 *)(r1 + 67) = r5

	PREPARE_PACKET_FOOTER
