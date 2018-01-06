	.include "xdp.S"

	r0 = 0xbb
	*(u8 *)(r10 - 5) = r0

	r0 = 0xaaaaaaaa
	*(u32 *)(r10 - 4) = r0

	r0 = *(u8 *)(r10 - 5)
	if r0 != 0xbb goto bad

	r0 = *(u8 *)(r10 - 4)
	if r0 != 0xaa goto bad
	r0 = *(u8 *)(r10 - 3)
	if r0 != 0xaa goto bad
	r0 = *(u8 *)(r10 - 2)
	if r0 != 0xaa goto bad
	r0 = *(u8 *)(r10 - 1)
	if r0 != 0xaa goto bad

	r0 = XDP_PASS
	exit
bad:
	r0 = XDP_DROP
	exit
