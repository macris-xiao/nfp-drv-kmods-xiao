.include "xdp.S"

xdp_prog1:
	r0 = 0

	r1 = 1
	r2 = 2
	call foo
	if r0 != 4 goto DROP

	r1 = 2
	r2 = 3
	call foo
	if r0 != 4 goto DROP

	r1 = 2
	r2 = 2
	call foo
	if r0 != 3 goto DROP

	r1 = 3
	r2 = 2
	call foo
	if r0 != 2 goto DROP

	r1 = 4
	r2 = 0
	call bar
	if r0 != 0 goto DROP

	r1 = 3
	r2 = 0
	call bar
	if r0 != 1 goto DROP

	r1 = 5
	r2 = 6
	call bar
	if r0 != 5 goto DROP

	r1 = 0
	r2 = 2
	call bar
	if r0 != 6 goto DROP

	r1 = 1
	r2 = 1
	call baz
	if r0 != 2 goto DROP

	r1 = -1
	r2 = 2
	call baz
	if r0 != 5 goto DROP

	r1 = 0
	r2 = 2
	call baz
	if r0 != 4 goto DROP

	r1 = 4
	r2 = 2
	call baz
	if r0 != 0 goto DROP

	r0 = XDP_PASS
	exit
DROP:
	r0 = XDP_DROP
	exit

/* CHECK-CODEGEN: .*rtn\[gprA_\d\] */
/* CHECK-CODEGEN: .*rtn\[gprA_\d\], defer\[\d\] */
/* CHECK-CODEGEN: .*rtn\[gprB_\d\], defer\[\d\] */

foo:
	r0 = 0
	r0 += 3
	r0 -= r1
	r0 += r2
	exit

bar:
	r0 = 0
	r7 = 4
	r9 = 3
	r0 += 3
	r0 -= r1
	r0 += r2
	r0 += r7
	r0 -= r9
	exit

baz:
	r0 = 0
	r6 = 1
	r7 = 4
	r8 = 5
	r9 = 3
	r0 += 3
	r0 -= r1
	r0 += r2
	r0 += r6
	r0 -= r7
	r0 += r8
	r0 -= r9
	exit
