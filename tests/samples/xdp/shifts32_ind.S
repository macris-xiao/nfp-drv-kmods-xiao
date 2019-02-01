	.macro SHIFT_STORE op, shift_amount, store_off
		r4 = *(u16 *)(r1 + 12)
		if r4 == 0 goto Lskip_init_r4_\store_off
		r4 = \shift_amount
		Lskip_init_r4_\store_off:
		r3 = r2
		w3 \op= w4
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 80
	if r3 > r2 goto out

	/* CHECK-CODEGEN: .*alu_shf\[.*, B,.* >>indirect\] */

	r2 = 0x1122334455667788 ll
	SHIFT_STORE <<,  0, 16
	SHIFT_STORE <<, "0x100000012 ll", 24
	SHIFT_STORE <<, 31, 32
	SHIFT_STORE <<, 39, 40

	r2 = 0x8122334455667788 ll
	SHIFT_STORE >>,  0, 48
	SHIFT_STORE >>, "0x10000001c ll", 56
	SHIFT_STORE >>, 29, 64
	SHIFT_STORE >>, 63, 72

	r0 = 2
out:
	exit
