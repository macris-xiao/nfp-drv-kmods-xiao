	.equ ALU32,	0
	.equ ALU64,	1

	.macro MUL16_REG_STORE multiplicand, multiplier, store_off, alu_type
		r2 = \multiplicand
		r3 = r2
		r4 = \multiplier
		.if \alu_type == ALU32
			w3 *= w4
		.else
			r3 *= r4
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	.macro MUL16_CONST_STORE multiplicand, multiplier, store_off, alu_type
		r2 = \multiplicand
		r3 = r2
		.if \alu_type == ALU32
			w3 *= \multiplier
		.else
			r3 *= \multiplier
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	/* CHECK-CODEGEN-NOT: .*32x32.* */

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 96
	if r3 > r2 goto out

	MUL16_REG_STORE 0x3344, 0x5566, 16, ALU64
	MUL16_REG_STORE 0x8877, 0x44, 24, ALU64
	MUL16_REG_STORE 0x112, 0x8556, 32, ALU64
	MUL16_REG_STORE 0x887, 0x433, 40, ALU64

	MUL16_CONST_STORE 0x3344, 0x5566, 48, ALU64
	MUL16_CONST_STORE 0x8877, 0x44, 56, ALU64
	MUL16_CONST_STORE 0x112, 0x8556, 64, ALU64
	MUL16_CONST_STORE 0x887, 0x433, 72, ALU64

	MUL16_REG_STORE 0x112, 0x8556, 80, ALU32
	MUL16_CONST_STORE 0x887, 0x433, 88, ALU32

	r0 = 2
out:
	exit
