	.macro SHIFT_STORE shift_amount, store_off
		r3 = r2
		w3 s>>= \shift_amount
		*(u64 *)(r1 + \store_off) = r3
	.endmacro

	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 64
	if r3 > r2 goto out

	r2 = 0x1122334485667788 ll

	SHIFT_STORE 1, 16
	SHIFT_STORE 7, 24
	SHIFT_STORE 31, 32

	r2 = 0x8122ffff55667788 ll
	SHIFT_STORE 4, 40
	SHIFT_STORE 15, 48
	SHIFT_STORE 29, 56

	r0 = 2
out:
	exit
