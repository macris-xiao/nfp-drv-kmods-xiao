.include "xdp.S"

xdp_prog1:
	r0 = 0

	r1 = 1
	r2 = 2
	call foobar
	if r0 != 4 goto DROP

	r1 = 2
	r2 = 3
	call foobar
	if r0 != 4 goto DROP

	r1 = 2
	r2 = 2
	call foobar
	if r0 != 3 goto DROP

	r1 = 3
	r2 = 2
	call foobar
	if r0 != 2 goto DROP

	r1 = 4
	r2 = 0
	call foobar
	if r0 != 0xffffffff goto DROP

	r1 = 3
	r2 = 0
	call foobar
	if r0 != 0 goto DROP

	r1 = 5
	r2 = 6
	call foobar
	if r0 != 4 goto DROP

	r1 = 0
	r2 = 2
	call foobar
	if r0 != 5 goto DROP

	r1 = 1
	r2 = 1
	call foobar
	if r0 != 3 goto DROP

	r1 = -1
	r2 = 2
	call foobar
	if r0 != 6 goto DROP

	r1 = 0
	r2 = 2
	call foobar
	if r0 != 5 goto DROP

	r1 = 4
	r2 = 2
	call foobar
	if r0 != 1 goto DROP

	r0 = XDP_PASS
	exit
DROP:
	r0 = XDP_DROP
	exit

foobar:
	r0 = 0
	r0 += 3
	r0 -= r1
	r0 += r2
	/* CHECK-CODEGEN: .*rtn\[gprA_\d\].* */
	exit
