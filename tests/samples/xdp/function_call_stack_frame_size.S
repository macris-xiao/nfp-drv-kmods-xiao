.include "xdp.S"

;_ As of the creation of this test, it fails if stack frames where to be
;_ aligned on any multiple of 32 bytes instead of 64. As writing into the stack
;_ uses a base pointer and an offset, and as the last bits are OR-ed, writing
;_ at 0x20 | 0x24 comes down to overwriting what was written at 0x20 | 0x04.
;_ The issue does not occur if stack frames are multiple of 64 bytes.

xdp_prog1:
	r1 = 0
	*(u32 *)(r10 - 16) = r1
	call foo
	if r0 != 0 goto DROP
	r0 = XDP_PASS
	exit
DROP:
	r0 = XDP_DROP
	exit

foo:
	r1 = 0xaa
	*(u32 *)(r10 - 0x04) = r1

	r3 = 0xee
	*(u32 *)(r10 - 0x24) = r3
	r2 = *(u32 *)(r10 - 0x24)
	if r2 != r3 goto fail

	r2 = *(u32 *)(r10 - 0x04)
	if r2 != r1 goto fail

	r3 = 0xff
	*(u32 *)(r10 - 0x44) = r3
	r2 = *(u32 *)(r10 - 0x44)
	if r2 != r3 goto fail

	r2 = *(u32 *)(r10 - 0x04)
	if r2 != r1 goto fail

/* CHECK-CODEGEN-TIMES-2: .*rtn\[gprA_\d\].* */
	r0 = 0
	exit
fail:
	r0 = -1
	exit
