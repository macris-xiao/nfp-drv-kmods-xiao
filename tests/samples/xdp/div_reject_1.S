	// When there are multiple code path, it is possible for divdend to be
	// constant on each code path but with different value. We should reject
	// such case as the dividend is still not runtime constant.
	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 96
	if r3 > r2 goto out
	r4 = *(u8 *)(r1 + 15)
	r5 = *(u8 *)(r1 + 16)
	if r4 < r5 goto L1
	if r4 > r5 goto L2
	r4 = 1
	goto L3
L1:
	r4 = 38
	goto L3
L2:
	r4 = 64
L3:
	r3 = 0x11223344
	r3 /= r4
	*(u64 *)(r1 + 24) = r3

	r0 = 2
out:
	exit
