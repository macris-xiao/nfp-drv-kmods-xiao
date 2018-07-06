	/* Reject multiplication by negative constant. */
	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 96
	if r3 > r2 goto out
	r3 = 0x11223344
	r3 *= -13
	*(u64 *)(r1 + 24) = r3

	r0 = 2
out:
	exit
