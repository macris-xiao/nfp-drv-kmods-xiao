.include "xdp.S"

	call live_call
	r0 = XDP_PASS
	exit

live_call:
	goto here
here:
	r0 = 1
	exit
