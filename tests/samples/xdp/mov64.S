	.include "xdp.S"

	r0 = 0x7777777777777777 ll

	r1 = 0x77777777
	r2 = r1
	r2 <<= 32
	r1 |= r2

	if r0 != r1 goto bad

	r0 = -1
	r1 = 0
	r1 -= 1

	if r0 != r1 goto bad

	r0 = XDP_PASS
	exit

bad:
	r0 = XDP_DROP
	exit
