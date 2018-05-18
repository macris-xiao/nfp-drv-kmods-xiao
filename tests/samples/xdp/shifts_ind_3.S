	.macro SHIFT_RAND_R4_AND_STORE op, off0, off1, label_idx, v1, v2, v3, store_off
		r4 = *(u8 *)(r1 + \off0)
		r5 = *(u8 *)(r1 + \off1)
		if r4 < r5 goto Llt_32_path_\label_idx
		if r4 > r5 goto Lgt_32_path_\label_idx
		r4 = \v1
		goto Lr4_init_finish_\label_idx
		Llt_32_path_\label_idx:
		r4 = \v2
		goto Lr4_init_finish_\label_idx
		Lgt_32_path_\label_idx:
		r4 = \v3
		Lr4_init_finish_\label_idx:
		r3 = r2
		r3 \op= r4
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	/* CHECK-CODEGEN-NOT: .*br_bset */

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 72
	if r3 > r2 goto out

	r2 = 0x1122334455667788 ll

	SHIFT_RAND_R4_AND_STORE <<, 15, 16, 0, 32, 33, 63, 24
	SHIFT_RAND_R4_AND_STORE <<, 17, 18, 1, 32, 33, 63, 32
	SHIFT_RAND_R4_AND_STORE <<, 19, 20, 2, 32, 33, 63, 40
	SHIFT_RAND_R4_AND_STORE >>, 15, 16, 3, 1, 31, 16, 48
	SHIFT_RAND_R4_AND_STORE >>, 17, 18, 4, 1, 31, 16, 56
	SHIFT_RAND_R4_AND_STORE >>, 19, 20, 5, 1, 31, 16, 64

	r0 = 2
out:
	exit
