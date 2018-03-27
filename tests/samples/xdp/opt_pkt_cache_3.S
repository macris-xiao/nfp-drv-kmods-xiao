// Test packet cache for long range which needs indirect ref

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	r2 = *(u8 *)(r1 + 14)
	r3 = *(u16 *)(r1 + 40)
	r4 = *(u32 *)(r1 + 43)
	r5 = *(u64 *)(r1 + 48)
	*(u8 *)(r1 + 60) = r2
	*(u16 *)(r1 + 61) = r3
	*(u32 *)(r1 + 63) = r4
	*(u64 *)(r1 + 67) = r5

	PREPARE_PACKET_FOOTER
