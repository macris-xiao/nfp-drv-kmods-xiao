// Test memory copy on:
//
//   valid sequence with different base registers.
//   valid sequence with negative offsets.

	.include "opt_memcpy_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// sequence descending order (41-bytes)
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x4c,.*\], ctx_swap */
	/* CHECK-CODEGEN: .*mem\[write8_swap,.*0x4d,.*\], ctx_swap */
	r4 = r1
	r2 = *(u8 *)(r1 + 78)
	*(u8 *)(r4 + 79) = r2
	r2 = *(u8 *)(r1 + 77)
	*(u8 *)(r4 + 78) = r2
	r2 = *(u8 *)(r1 + 76)
	*(u8 *)(r4 + 77) = r2

	/* CHECK-CODEGEN: .*mem\[write8_swap,.*0x48,.*5\], ctx_swap */
	r1 += 75
	r2 = *(u8 *)(r1 + 0)
	*(u8 *)(r4 + 76) = r2
	r2 = *(u8 *)(r1 - 1)
	*(u8 *)(r4 + 75) = r2
	r2 = *(u8 *)(r1 - 2)
	*(u8 *)(r4 + 74) = r2
	r2 = *(u8 *)(r1 - 3)
	*(u8 *)(r4 + 73) = r2
	r2 = *(u8 *)(r1 - 4)
	*(u8 *)(r4 + 72) = r2

	/* CHECK-CODEGEN: .*mem\[write8_swap,.*7\], ctx_swap */
	r2 = *(u8 *)(r1 - 5)
	*(u8 *)(r1 - 4) = r2
	r2 = *(u8 *)(r1 - 6)
	*(u8 *)(r1 - 5) = r2
	r2 = *(u8 *)(r1 - 7)
	*(u8 *)(r1 - 6) = r2
	r2 = *(u8 *)(r1 - 8)
	*(u8 *)(r1 - 7) = r2
	r2 = *(u8 *)(r1 - 9)
	*(u8 *)(r1 - 8) = r2
	r2 = *(u8 *)(r1 - 10)
	*(u8 *)(r1 - 9) = r2
	r2 = *(u8 *)(r1 - 11)
	*(u8 *)(r1 - 10) = r2

	/* CHECK-CODEGEN: .*mem\[write8_swap,.*3\], ctx_swap */
	r2 = *(u8 *)(r1 - 75 + 14 + 3)
	*(u8 *)(r1 - 75 + 14 + 0) = r2
	r2 = *(u8 *)(r1 - 75 + 14 + 4)
	*(u8 *)(r1 - 75 + 14 + 1) = r2
	r2 = *(u8 *)(r1 - 75 + 14 + 5)
	*(u8 *)(r1 - 75 + 14 + 2) = r2

	// r1 will be used by footer, restore the original value.
	r1 -= 75
	PREPARE_PACKET_FOOTER
