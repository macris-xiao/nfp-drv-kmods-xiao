# Test memory copy optimization on:
#
#   copy length <= 32-bytes.
#   copy length is not 4-byte aligned.
#   copy elem width is half-word.

	.include "opt_memcpy_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	# sequence in ascending order (18-bytes)
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x25, 5\], ctx_swap */
	/* CHECK-CODEGEN: .*alu\[\$xfer_4, \-\-, B, \$xfer_4\] */
	/* CHECK-CODEGEN: .*immed\[\-\-, 0x1180\] */
	/* CHECK-CODEGEN: .*mem\[write8_swap,.*0x13,.*\], indirect_ref */
	/* CHECK-CODEGEN-NOT: .*alu\[\$xfer_5, \-\-, B, \$xfer_5\] */
	r2 = *(u16 *)(r1 + 37)
	*(u16 *)(r1 + 19) = r2
	r2 = *(u16 *)(r1 + 39)
	*(u16 *)(r1 + 21) = r2
	r2 = *(u16 *)(r1 + 41)
	*(u16 *)(r1 + 23) = r2
	r2 = *(u16 *)(r1 + 43)
	*(u16 *)(r1 + 25) = r2
	r2 = *(u16 *)(r1 + 45)
	*(u16 *)(r1 + 27) = r2
	r2 = *(u16 *)(r1 + 47)
	*(u16 *)(r1 + 29) = r2
	r2 = *(u16 *)(r1 + 49)
	*(u16 *)(r1 + 31) = r2
	r2 = *(u16 *)(r1 + 51)
	*(u16 *)(r1 + 33) = r2
	r2 = *(u16 *)(r1 + 53)
	*(u16 *)(r1 + 35) = r2

	# data flow integrity check
	r2 += 1
	*(u16 *)(r1 + 35) = r2

	PREPARE_PACKET_FOOTER
