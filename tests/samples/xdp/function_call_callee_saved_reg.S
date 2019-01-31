.include "xdp.S"

xdp_prog1:
	r6 = 0x1111
	r7 = 0x2222
	r8 = 0x3333
	r9 = 0x4444

	r0 = 0
	r1 = 0
	r2 = 1
	call add_0
	if r0 != 1 goto DROP
	r9 += r8
	r9 += r7
	r9 += r6
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = 0
	r1 = 0
	r2 = 1
	call add_1
	if r0 != 1 goto DROP
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = 0
	r1 = 0
	r2 = 1
	call add_2
	if r0 != 1 goto DROP
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = 0
	r1 = 0
	r2 = 1
	call add_3
	if r0 != 1 goto DROP
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = 0
	r1 = 0
	r2 = 1
	call add_4
	if r0 != 1 goto DROP
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = 0
	r1 = 0
	r2 = 1
	call add_nested
	if r0 != 1 goto DROP
	if r6 != 0x1111 goto DROP
	if r7 != 0x2222 goto DROP
	if r8 != 0x3333 goto DROP
	if r9 != 0xaaaa goto DROP

	r0 = XDP_PASS
	exit
DROP:
	r0 = XDP_DROP
	exit

/* CHECK-CODEGEN: .*rtn\[gprA_\d\] */
/* CHECK-CODEGEN: .*rtn\[gprA_\d\], defer\[\d\] */
/* CHECK-CODEGEN: .*rtn\[gprB_\d\], defer\[\d\] */

add_0:
// int add_0(int a, int b) { return a + b; }
	r0 = r1
	r0 += r2
	exit
// }

add_1:
	r0 = r1
	r6 = 0xffff
	if r6 < r2 goto RET_1
	r0 += r2
RET_1:
	exit

add_2:
	r0 = r1
	r7 = 0xffff
	r9 = 0xabcd
	if r7 < r9 goto RET_2
	if r9 != 0xabcd goto RET_2
	r0 += r2
RET_2:
	exit

add_3:
	r0 = r1
	r6 = 0xffff
	r8 = 0x1234
	r9 = 0x0001
	if r6 < r9 goto RET_3
	if r8 != 0x1234 goto RET_3
	r0 += r2
RET_3:
	exit

add_4:
	r0 = r1
	r6 = 0xffff
	r7 = 0xabcd
	r8 = 0x1234
	r9 = 0x0001
	if r6 < r9 goto RET_4
	if r7 != 0xabcd goto RET_4
	if r8 != 0x1234 goto RET_4
	r0 += r2
RET_4:
	exit

add_nested:
	r0 = r1
	*(u32 *)(r10 - 4) = r1
	*(u32 *)(r10 - 8) = r2
	r6 = 0xffff
	r7 = 0xabcd
	r8 = 0x1234
	r9 = 0x0001
	call nested_function
	r1 = *(u32 *)(r10 - 4)
	r2 = *(u32 *)(r10 - 8)
	if r0 != r1 goto RET_nested
	if r6 < r9 goto RET_nested
	if r7 != 0xabcd goto RET_nested
	if r8 != 0x1234 goto RET_nested
	r0 += r2
RET_nested:
	exit

nested_function:
	r7 = 0x7777
	r8 = 0x8888
	r0 = r1
	exit
