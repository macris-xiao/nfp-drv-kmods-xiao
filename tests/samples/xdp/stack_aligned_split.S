	.include "xdp.S"
	.include "stack_helpers.S"

	.macro CHECK_CONTENTS _const1, _const2
		r2 = r10

		r1 = \_const1 ll
		.rep 8
			r2 += -8
			r0 = *(u64 *)(r2 + 0)
			if r0 != r1 goto bad
		.endr

		r1 = \_const2 ll
		.rep 8
			r2 += -8
			r0 = *(u64 *)(r2 + 0)
			if r0 != r1 goto bad
		.endr
	.endm

	STACK_INIT_CONST 64, 0, r3, r0
	STACK_INIT_CONST 64, 0x1234567890abcdef, r3, r0, r3

	CHECK_CONTENTS 0, 0x1234567890abcdef

	STACK_INIT_CONST 64, 0xabc, r3, r0

	CHECK_CONTENTS 0xabc, 0x1234567890abcdef

	STACK_INIT_CONST 64, 0x123, r3, r0, r3

	CHECK_CONTENTS 0xabc, 0x123

	r0 = XDP_PASS
	exit
bad:
	r0 = XDP_DROP
	exit
