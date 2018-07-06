	.equ ALU32,	0
	.equ ALU64,	1

	.macro DIV32_REG_STORE divided, divisor, store_off, alu_type
		r2 = \divided ll
		r3 = r2
		r4 = \divisor ll
		.if \alu_type == ALU32
			w3 /= w4
		.else
			r3 /= r4
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	.macro DIV32_CONST_STORE divided, divisor, store_off, alu_type
		r2 = \divided ll
		r3 = r2
		.if \alu_type == ALU32
			w3 /= \divisor
		.else
			r3 /= \divisor
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 96
	if r3 > r2 goto out

	DIV32_CONST_STORE 0x11223344, 1, 16, ALU64
	DIV32_CONST_STORE 0x11223344, 0x7fffffff, 24, ALU64
	DIV32_CONST_STORE 0x81223344, 64, 32, ALU64
	DIV32_CONST_STORE 0x81223344, 0x1121, 40, ALU64

	// the range info could tell us the divisor is constant.
	DIV32_REG_STORE 0x11223344, 1, 48, ALU64
	DIV32_REG_STORE 0x11223344, 38, 56, ALU64
	DIV32_REG_STORE 0x81223344, 64, 64, ALU64
	DIV32_REG_STORE 0x81223344, 0x7fffffff, 72, ALU64

	DIV32_CONST_STORE 0x81223344, 0x1121, 80, ALU32
	DIV32_REG_STORE 0x81223344, 64, 88, ALU32

	r0 = 2
out:
	exit
