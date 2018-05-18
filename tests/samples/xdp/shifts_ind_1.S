	.macro SHIFT_STORE op, shift_amount, store_off
		r3 = r2
		r4 = \shift_amount
		r3 \op= r4
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	/* CHECK-CODEGEN-NOT: .*br_bset */

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 64
	if r3 > r2 goto out

	r2 = 0x1122334455667788 ll

	SHIFT_STORE <<, 5, 16
	SHIFT_STORE <<, 32, 24
	SHIFT_STORE <<, 63, 32
	SHIFT_STORE >>, 1, 40
	SHIFT_STORE >>, 32, 48
	SHIFT_STORE >>, 33, 56

	r0 = 2
out:
	exit
