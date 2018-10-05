.include "xdp.S"

xdp_prog1:
	r1 = 0
	*(u32 *)(r10 - 16) = r1
	call foo
	exit

.equ LOOPS, 17
foo:
	r5 = r10
	r1 = 0
	.rep LOOPS
	r1 += 4
	r5 += -4
	*(u32 *)(r5 - 0) = r1
	.endr

	r5 = r10
	r1 = 0
	.rep LOOPS
	r1 += 4
	r5 += -4
	r2 = *(u32 *)(r5 - 0)
	if r2 != r1 goto fail
	.endr

/* CHECK-CODEGEN-TIMES-2: .*rtn\[gprA_\d\].* */
	r0 = XDP_PASS
	exit
fail:
	r0 = XDP_DROP
	exit
