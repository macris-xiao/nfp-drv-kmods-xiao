	r2 = 0
	if r2 == 0 goto skip_bad_call

	// START DEAD CODE
	r2 = *(u32 *)(r1 + 4) // load packet start and end
	r1 = *(u32 *)(r1 + 0) // just to have some non-constants

	goto forward
backward:
	r0 = 0
	goto skip_bad_call
forward:
	if r2 > r1 goto backward
	// END DEAD CODE

skip_bad_call:
	r0 = 2
	exit
