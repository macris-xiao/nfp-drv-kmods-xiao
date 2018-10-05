.include "xdp.S"

xdp_prog1:
	r1 = 0
	*(u32 *)(r10 - 16) = r1
	call foo
	exit

.equ LOOPS, 65
foo:
	r5 = r10
	r1 = 0
	.rep LOOPS
		r1 += 1
		r5 += -1
		*(u8 *)(r5 - 0) = r1
	.endr

	r5 = r10
	r1 = 0
	.rep LOOPS
		r1 += 1
		r5 += -1
		r2 = *(u8 *)(r5 - 0)
		if r2 != r1 goto fail
	.endr

/* CHECK-CODEGEN-TIMES-2: .*rtn\[gprA_\d\].* */
	r0 = XDP_PASS
	exit
fail:
	r0 = XDP_DROP
	exit
