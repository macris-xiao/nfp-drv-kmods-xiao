	r2 = 0
	if r2 == 0 goto skip_bad_call

	// START DEAD CODE
	call 2000 // helper which doesn't exist at all
	// END DEAD CODE

skip_bad_call:
	r0 = 2
	exit
