// Test various cache invalidations.

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	r2 = *(u8 *)(r1 + 14)
	r3 = *(u16 *)(r1 + 40)

	// Different constant offset.
	r7 = r1
	r7 += 16
	r5 = *(u8 *)(r7 + 14)
	r6 = *(u16 *)(r7 + 40)

	// Interleaved with memcpy sequence.
	r4 = *(u8 *)(r1 + 15)
	*(u8 *)(r1 + 22) = r4
	r4 = *(u8 *)(r1 + 16)
	*(u8 *)(r1 + 23) = r4
	r4 = *(u8 *)(r1 + 17)
	*(u8 *)(r1 + 24) = r4
	r4 = *(u8 *)(r1 + 18)
	*(u8 *)(r1 + 25) = r4
	r4 = *(u8 *)(r1 + 19)
	*(u8 *)(r1 + 26) = r4
	r4 = *(u8 *)(r1 + 20)
	*(u8 *)(r1 + 27) = r4
	r4 = *(u8 *)(r1 + 21)
	*(u8 *)(r1 + 28) = r4
	r8 = *(u8 *)(r7 + 14)
	r9 = *(u16 *)(r7 + 40)
	*(u8 *)(r1 + 60) = r2
	*(u16 *)(r1 + 61) = r3
	*(u8 *)(r1 + 63) = r5
	*(u16 *)(r1 + 64) = r6
	*(u8 *)(r1 + 66) = r8
	*(u16 *)(r1 + 67) = r9

	r2 = *(u8 *)(r7 + 14)
	r3 = *(u16 *)(r7 + 40)
	// Interleaved with store.
	r4 = 0
	*(u8 *)(r7 + 14) = r4
	r4 = *(u8 *)(r7 + 14)
	*(u8 *)(r1 + 69) = r2
	*(u16 *)(r1 + 70) = r3
	*(u8 *)(r1 + 72) = r4

	PREPARE_PACKET_FOOTER
