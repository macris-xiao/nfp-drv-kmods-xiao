.include "xdp.S"

	goto here
here:
	r0 = XDP_PASS
	exit
