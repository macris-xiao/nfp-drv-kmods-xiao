	.equ ALU32,	0
	.equ ALU64,	1

	.macro MUL32_REG_STORE multiplicand, multiplier, store_off, alu_type
		r2 = \multiplicand ll
		r3 = r2
		r4 = \multiplier ll
		.if \alu_type == ALU32
			w3 *= w4
		.else
			r3 *= r4
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	.macro MUL32_CONST_STORE multiplicand, multiplier, store_off, alu_type
		r2 = \multiplicand ll
		r3 = r2
		.if \alu_type == ALU32
			w3 *= \multiplier
		.else
			r3 *= \multiplier
		.endif
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 96
	if r3 > r2 goto out

	MUL32_REG_STORE 0x11223344, 0x55667788, 16, ALU64
	MUL32_REG_STORE 0x88776655, 0x44332211, 24, ALU64
	MUL32_REG_STORE 0x11223344, 0x556, 32, ALU64
	MUL32_REG_STORE 0x887, 0x84332211, 40, ALU64

	MUL32_CONST_STORE 0x11223344, 0x55667788, 48, ALU64
	// Make sure unrestricted operand used, we could encode 8-bit imm.
	/* CHECK-CODEGEN: .*mul_step\[.*, 0xa0\], start */
	MUL32_CONST_STORE 0x88776655, 0xa0, 56, ALU64
	MUL32_CONST_STORE 0x11223344, 0x556, 64, ALU64
	MUL32_CONST_STORE 0x887, 0x74332211, 72, ALU64

	MUL32_REG_STORE 0x88776655, 0x44332211, 80, ALU32
	MUL32_CONST_STORE 0x11223344, -1088, 88, ALU32

	r0 = 2
out:
	exit
