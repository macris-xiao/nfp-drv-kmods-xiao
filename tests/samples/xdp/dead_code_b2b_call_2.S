.include "xdp.S"

	r2 = 0
	if r2 == 0 goto skip_bad_call

	/* CHECK-CODEGEN-NOT: .*beq\[.* */

	// START DEAD CODE
	call dead_call
	// END DEAD CODE

skip_bad_call:
	call live_call

	r0 = XDP_PASS
	exit

dead_call:
	r0 = 100 // we ain't got no DIV on the NFP
	r0 /= 2
	exit

live_call:
	r0 = 1
	exit
