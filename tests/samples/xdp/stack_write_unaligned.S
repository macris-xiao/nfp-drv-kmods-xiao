	.include "xdp.S"

	r0 = 0
	*(u16 *)(r10 - 15) = r0

	r0 = XDP_PASS
	exit
