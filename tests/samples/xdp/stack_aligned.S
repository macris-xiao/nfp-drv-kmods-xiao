	.include "xdp.S"
	.include "stack_helpers.S"

	STACK_INIT_SIMPLE 128, r0

	r2 = r10

	.rep 4
		r1 = 0x1234567890abcdef ll
		r0 = *(u64 *)(r2 -  8)
		if r0 != r1 goto bad
		r0 = *(u64 *)(r2 - 16)
		if r0 != r1 goto bad

		r1 = 0xfedcba0123456789 ll
		r0 = *(u64 *)(r2 - 24)
		if r0 != r1 goto bad
		r0 = *(u64 *)(r2 - 32)
		if r0 != r1 goto bad

		r2 += -32
	.endr

	r0 = XDP_PASS
	exit
bad:
	r0 = XDP_DROP
	exit
