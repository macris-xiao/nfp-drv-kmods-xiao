.include "xdp.S"

	r2 = 0
	if r2 == 1 goto dead_code

	r0 = XDP_PASS
	exit

dead_code:
	call 1234
	r0 = XDP_DROP
	exit
