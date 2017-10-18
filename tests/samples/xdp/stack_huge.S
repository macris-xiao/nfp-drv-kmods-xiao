	.include "xdp.S"

	r0 = XDP_PASS

	*(u64 *)(r10 - 8) = r0
	*(u64 *)(r10 - 512) = r0

	exit
