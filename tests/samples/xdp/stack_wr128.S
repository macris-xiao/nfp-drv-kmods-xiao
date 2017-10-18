	.include "xdp.S"
	.include "stack_helpers.S"

	STACK_INIT_SIMPLE 128, r0

	r0 = XDP_PASS
	exit
