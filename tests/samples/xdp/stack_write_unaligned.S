	.include "xdp.S"

	.equ TRASH,	0xbbbbbbbbbbbbbbbb

	.macro CALC_RESULT _a, _b, _size, _off
		r1 = 0 + ((\_a >> (64 - \_off * 8)) | (\_b << (\_off * 8))) ll
	.endm

	.macro CHECK_OFFSET2 _c1, _c2, _size, _off, _err, _wr_ptr

		;; init to trash
		r0 = TRASH ll
		*(u64 *)(\_wr_ptr -  8) = r0
		*(u64 *)(\_wr_ptr - 16) = r0

		r0 = 0 + \_c1 ll
		*(u\_size *)(\_wr_ptr - 16 + \_off) = r0

		r0 = *(u64 *)(\_wr_ptr -  8)
		CALC_RESULT \_c2, TRASH, \_size, \_off
		if r0 != r1 goto \_err

		r0 = *(u64 *)(\_wr_ptr -  16)
		CALC_RESULT TRASH, \_c2, \_size, \_off
		if r0 != r1 goto \_err
		r0 = 0
		r0 = 0
		r0 = 0
		r0 = 0
		r0 = 0
	.endm

	.macro CHECK_OFFSET _const, _size, _off, _err, _wr_ptr
	.if \_size == 64
	CHECK_OFFSET2 \_const, \_const, \_size, \_off, \_err, \_wr_ptr
	.else
	CHECK_OFFSET2 \_const, ((\_const & (1 << \_size - 1)) | (TRASH << (\_size))), \_size, \_off, \_err, \_wr_ptr
	.endif
	.endm

	.macro TEST _const, _size, _wr_ptr=r10

		CHECK_OFFSET \_const, \_size, 1, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 2, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 3, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 4, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 5, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 6, bad, \_wr_ptr
		CHECK_OFFSET \_const, \_size, 7, bad, \_wr_ptr

		r0 = XDP_PASS
		exit

	bad:
		r0 = XDP_DROP
		exit
	.endm
