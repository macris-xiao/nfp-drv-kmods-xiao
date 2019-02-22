// ALU imm code-gen has a couple of small optimizations listed below, this test
// make sure they work as expected.
//
//   A &  0 =  0
//   A & -1 =  A
//   A |  0 =  A
//   A | -1 = -1
//   A ^  0 =  A
//   A ^ -1 = ~A

	.macro TEST op, imm, store_off
		r7 = r2
		r7 \op= \imm
		*(u64 *)(r1 + \store_off) = r7
		r7 = r2
		w7 \op= \imm
		*(u64 *)(r1 + \store_off + 8) = r7
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 112
	if r3 > r2 goto out

	r2 = 0x8877665544332211 ll
	TEST &,  0, 16
	TEST &, -1, 32
	TEST |,  0, 48
	TEST |, -1, 64
	TEST ^,  0, 80
	TEST ^, -1, 96

	/* CHECK-CODEGEN-NOT: .*alu\[gpr.*14, AND.* */
	/* CHECK-CODEGEN-NOT: .*alu\[gpr.*14, OR.* */
	/* CHECK-CODEGEN-NOT: .*alu\[gpr.*14, XOR.* */

	r0 = 2
out:
	exit
