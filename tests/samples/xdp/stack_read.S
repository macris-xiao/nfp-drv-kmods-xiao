	.include "xdp.S"

	.macro CHECK_OFFSET2 _c1, _c2, _size, _mask, _off, _err, _rd_ptr
		r1 = 0 + (\_c1 >> (\_off * 8) | \_c2 << ((8 - \_off) * 8)) & \_mask ll
		// init to trash to validate clearing upper parts
		r0 = 0xbbbbbbbbbbbbbbbb ll
		r0 = *(\_size *)(\_rd_ptr - 16 + \_off)
		if r0 != r1 goto \_err
	.endm

	.macro CHECK_OFFSET _c1, _c2, _sz, _off, _err, _rd_ptr
	// kernel does not currently allow unaligned stack accesses
	.if \_off % (\_sz / 8) == 0
	CHECK_OFFSET2 \_c1, \_c2, u\_sz, (0xffffffffffffffff >> (64 - \_sz)), \_off, \_err, \_rd_ptr
	.endif
	.endm

	.macro TEST _c1, _c2, _sz, _rd_ptr=r10

		r0 = \_c1 ll
		*(u64 *)(r10 - 16) = r0
		r0 = \_c2 ll
		*(u64 *)(r10 -  8) = r0

		CHECK_OFFSET \_c1, \_c2, \_sz, 1, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 2, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 3, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 4, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 5, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 6, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 7, bad, \_rd_ptr
		CHECK_OFFSET \_c1, \_c2, \_sz, 8, bad, \_rd_ptr

		r0 = XDP_PASS
		exit

	bad:
		r0 = XDP_DROP
		exit
	.endm
