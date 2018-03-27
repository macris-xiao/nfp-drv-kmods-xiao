// Test packet cache for unaligned offsets with negative offset

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	r1 += 20

	r2 = *(u8 *)(r1 - 20 + 14)
	// unaligned DW_B
	r3 = *(u8 *)(r1 - 20 + 15)
	r4 = *(u8 *)(r1 - 20 + 16)
	r5 = *(u8 *)(r1 - 20 + 17)

	*(u8 *)(r1 - 20 + 25) = r2
	*(u8 *)(r1 - 20 + 26) = r3
	*(u8 *)(r1 - 20 + 27) = r4
	*(u8 *)(r1 - 20 + 28) = r5

	r2 = *(u16 *)(r1 - 20 + 14)
	// unaligned DW_H
	r3 = *(u16 *)(r1 - 20 + 15)
	r4 = *(u16 *)(r1 - 20 + 16)
	r5 = *(u16 *)(r1 - 20 + 17)
	*(u16 *)(r1 - 20 + 29) = r2
	*(u16 *)(r1 - 20 + 31) = r3
	*(u16 *)(r1 - 20 + 33) = r4
	*(u16 *)(r1 - 20 + 35) = r5

	r2 = *(u32 *)(r1 - 20 + 14)
	// unaligned DW_W
	r3 = *(u32 *)(r1 - 20 + 15)
	r4 = *(u32 *)(r1 - 20 + 16)
	r5 = *(u32 *)(r1 - 20 + 17)
	*(u32 *)(r1 - 20 + 37) = r2
	*(u32 *)(r1 - 20 + 41) = r3
	*(u32 *)(r1 - 20 + 45) = r4
	*(u32 *)(r1 - 20 + 49) = r5

	r2 = *(u64 *)(r1 - 20 + 14)
	// unaligned DW_DW
	r3 = *(u64 *)(r1 - 20 + 15)
	r4 = *(u64 *)(r1 - 20 + 16)
	r5 = *(u64 *)(r1 - 20 + 17)
	*(u64 *)(r1 - 20 + 53) = r2
	*(u64 *)(r1 - 20 + 61) = r3
	*(u64 *)(r1 - 20 + 69) = r4
	*(u64 *)(r1 - 20 + 77) = r5

	r1 -= 20
	PREPARE_PACKET_FOOTER
