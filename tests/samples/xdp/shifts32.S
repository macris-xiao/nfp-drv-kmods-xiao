	.macro SHIFT_STORE op, shift_amount, store_off
		r3 = r2
		r4 = \shift_amount
		w3 \op= w4
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 80
	if r3 > r2 goto out

	// Shifts by register with known constant should have been optimized
	// into shifts by immediate. Also, high bits should not affect shift
	// amount.

	/* CHECK-CODEGEN-NOT: .*alu_shf\[.*, B,.* >>indirect\] */

	r2 = 0x1122334455667788 ll
	SHIFT_STORE <<,  0, 16
	SHIFT_STORE <<,  7, 24
	SHIFT_STORE <<, "0x100000012 ll", 32
	SHIFT_STORE <<, 31, 40

	r2 = 0x8122334455667788 ll
	SHIFT_STORE >>,  0, 48
	SHIFT_STORE >>,  1, 56
	SHIFT_STORE >>, "0x10000001c ll", 64
	SHIFT_STORE >>, 29, 72

	r0 = 2
out:
	exit
