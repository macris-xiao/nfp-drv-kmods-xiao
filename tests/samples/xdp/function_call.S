.include "xdp.S"

main:
	call callee
	if r0 != 0xf00 goto DROP
	r0 = XDP_PASS
	exit
DROP:
	r0 = XDP_DROP
	exit

callee:
	/* CHECK-CODEGEN: .*rtn\[gprA_\d\].* */
	r0 = 0xf00
	exit
