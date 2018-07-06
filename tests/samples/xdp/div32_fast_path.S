	.macro DIV32_STORE divided, divisor, store_off
		r2 = \divided ll
		r3 = r2
		r2 = \divisor ll
		r3 /= r2
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 80
	if r3 > r2 goto out

	/* CHECK-CODEGEN-TIMES-4: .*32x32_last2.* */
	/* CHECK-CODEGEN-TIMES-1: .*alu_shf\[.*, >>6\].* */
	/* CHECK-CODEGEN-TIMES-1: .*alu\[.*\+, gpr.* */

	DIV32_STORE 0x11223344, 7, 16
	DIV32_STORE 0x11223344, 10, 24
	DIV32_STORE 0x81223344, 14, 32
	DIV32_STORE 0x81223344, 64, 40
	DIV32_STORE 0x81223344, 0x1220, 48
	DIV32_STORE 0x81223344, 0x80000000, 56
	DIV32_STORE 0x81223344, 0x82223344, 64
	DIV32_STORE 0x81223344, 0x81223343, 72

	r0 = 2
out:
	exit
