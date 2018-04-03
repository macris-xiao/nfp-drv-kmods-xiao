// Test packet cache for unaligned offsets
/* CHECK-CODEGEN-TIMES-7: .*mem\[read32_swap,.*\], ctx_swap */

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	r2 = *(u8 *)(r1 + 14)
	// unaligned DW_B
	r3 = *(u8 *)(r1 + 15)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0xf,.*\], ctx_swap */
	r4 = *(u8 *)(r1 + 16)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x10,.*\], ctx_swap */
	r5 = *(u8 *)(r1 + 17)
	/* CHECK-CODEGEN-NOT: .*mem\[read32_swap,.*0x11,.*\], ctx_swap */

	*(u8 *)(r1 + 25) = r2
	*(u8 *)(r1 + 26) = r3
	*(u8 *)(r1 + 27) = r4
	*(u8 *)(r1 + 28) = r5

	r2 = *(u16 *)(r1 + 14)
	// unaligned DW_H
	r3 = *(u16 *)(r1 + 15)
	r4 = *(u16 *)(r1 + 16)
	r5 = *(u16 *)(r1 + 17)
	*(u16 *)(r1 + 29) = r2
	*(u16 *)(r1 + 31) = r3
	*(u16 *)(r1 + 33) = r4
	*(u16 *)(r1 + 35) = r5

	r2 = *(u32 *)(r1 + 14)
	// unaligned DW_W
	r3 = *(u32 *)(r1 + 15)
	r4 = *(u32 *)(r1 + 16)
	r5 = *(u32 *)(r1 + 17)
	*(u32 *)(r1 + 37) = r2
	*(u32 *)(r1 + 41) = r3
	*(u32 *)(r1 + 45) = r4
	*(u32 *)(r1 + 49) = r5

	r2 = *(u64 *)(r1 + 14)
	// unaligned DW_DW
	r3 = *(u64 *)(r1 + 15)
	r4 = *(u64 *)(r1 + 16)
	r5 = *(u64 *)(r1 + 17)
	*(u64 *)(r1 + 53) = r2
	*(u64 *)(r1 + 61) = r3
	*(u64 *)(r1 + 69) = r4
	*(u64 *)(r1 + 77) = r5

	PREPARE_PACKET_FOOTER
