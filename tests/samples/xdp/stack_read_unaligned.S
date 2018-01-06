	.include "xdp.S"

	r0 = 0
	*(u64 *)(r10 - 16) = r0
	r1 = *(u16 *)(r10 - 15)

	r0 = XDP_PASS
	exit
