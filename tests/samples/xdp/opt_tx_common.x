.macro PREPARE_PACKET_HEADER
	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 94
	if r3 > r2 goto LBB0_3
	r0 = 1
	r2 = *(u16 *)(r1 + 12)
	if r2 != 8722 goto LBB0_3
	r2 = 13330
	*(u16 *)(r1 + 12) = r2
.endm

.macro PREPARE_PACKET_FOOTER
	r2 = *(u32 *)(r1 + 0)
	r3 = *(u32 *)(r1 + 6)
	*(u32 *)(r1 + 0) = r3
	*(u32 *)(r1 + 6) = r2
	r2 = *(u16 *)(r1 + 4)
	r3 = *(u16 *)(r1 + 10)
	*(u16 *)(r1 + 4) = r3
	*(u16 *)(r1 + 10) = r2
	r0 = 3
LBB0_3:
	exit
.endm
