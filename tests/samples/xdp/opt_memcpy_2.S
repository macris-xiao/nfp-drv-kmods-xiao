// Test memory copy on:
//
//   copy length > 40-bytes
//   copy length is not 4-byte aligned.
//   copy elem width is byte.

	.include "opt_tx_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	// sequence descending order (41-bytes)
	/* CHECK-CODEGEN: .*immed\[\-\-, 0xa80\] */
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x26,.*\], indirect_ref, ctx_swap */
	/* CHECK-CODEGEN: .*alu\[\$xfer_10, \-\-, B, \$xfer_10\] */
	/* CHECK-CODEGEN: .*immed\[\-\-, 0x980\] */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0x27,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*mem\[write8_swap,.*0x4f,.*\], ctx_swap */
	r2 = *(u8 *)(r1 + 78)
	*(u8 *)(r1 + 79) = r2
	r2 = *(u8 *)(r1 + 77)
	*(u8 *)(r1 + 78) = r2
	r2 = *(u8 *)(r1 + 76)
	*(u8 *)(r1 + 77) = r2
	r2 = *(u8 *)(r1 + 75)
	*(u8 *)(r1 + 76) = r2
	r2 = *(u8 *)(r1 + 74)
	*(u8 *)(r1 + 75) = r2
	r2 = *(u8 *)(r1 + 73)
	*(u8 *)(r1 + 74) = r2
	r2 = *(u8 *)(r1 + 72)
	*(u8 *)(r1 + 73) = r2
	r2 = *(u8 *)(r1 + 71)
	*(u8 *)(r1 + 72) = r2
	r2 = *(u8 *)(r1 + 70)
	*(u8 *)(r1 + 71) = r2
	r2 = *(u8 *)(r1 + 69)
	*(u8 *)(r1 + 70) = r2
	r2 = *(u8 *)(r1 + 68)
	*(u8 *)(r1 + 69) = r2
	r2 = *(u8 *)(r1 + 67)
	*(u8 *)(r1 + 68) = r2
	r2 = *(u8 *)(r1 + 66)
	*(u8 *)(r1 + 67) = r2
	r2 = *(u8 *)(r1 + 65)
	*(u8 *)(r1 + 66) = r2
	r2 = *(u8 *)(r1 + 64)
	*(u8 *)(r1 + 65) = r2
	r2 = *(u8 *)(r1 + 63)
	*(u8 *)(r1 + 64) = r2
	r2 = *(u8 *)(r1 + 62)
	*(u8 *)(r1 + 63) = r2
	r2 = *(u8 *)(r1 + 61)
	*(u8 *)(r1 + 62) = r2
	r2 = *(u8 *)(r1 + 60)
	*(u8 *)(r1 + 61) = r2
	r2 = *(u8 *)(r1 + 59)
	*(u8 *)(r1 + 60) = r2
	r2 = *(u8 *)(r1 + 58)
	*(u8 *)(r1 + 59) = r2
	r2 = *(u8 *)(r1 + 57)
	*(u8 *)(r1 + 58) = r2
	r2 = *(u8 *)(r1 + 56)
	*(u8 *)(r1 + 57) = r2
	r2 = *(u8 *)(r1 + 55)
	*(u8 *)(r1 + 56) = r2
	r2 = *(u8 *)(r1 + 54)
	*(u8 *)(r1 + 55) = r2
	r2 = *(u8 *)(r1 + 53)
	*(u8 *)(r1 + 54) = r2
	r2 = *(u8 *)(r1 + 52)
	*(u8 *)(r1 + 53) = r2
	r2 = *(u8 *)(r1 + 51)
	*(u8 *)(r1 + 52) = r2
	r2 = *(u8 *)(r1 + 50)
	*(u8 *)(r1 + 51) = r2
	r2 = *(u8 *)(r1 + 49)
	*(u8 *)(r1 + 50) = r2
	r2 = *(u8 *)(r1 + 48)
	*(u8 *)(r1 + 49) = r2
	r2 = *(u8 *)(r1 + 47)
	*(u8 *)(r1 + 48) = r2
	r2 = *(u8 *)(r1 + 46)
	*(u8 *)(r1 + 47) = r2
	r2 = *(u8 *)(r1 + 45)
	*(u8 *)(r1 + 46) = r2
	r2 = *(u8 *)(r1 + 44)
	*(u8 *)(r1 + 45) = r2
	r2 = *(u8 *)(r1 + 43)
	*(u8 *)(r1 + 44) = r2
	r2 = *(u8 *)(r1 + 42)
	*(u8 *)(r1 + 43) = r2
	r2 = *(u8 *)(r1 + 41)
	*(u8 *)(r1 + 42) = r2
	r2 = *(u8 *)(r1 + 40)
	*(u8 *)(r1 + 41) = r2
	r2 = *(u8 *)(r1 + 39)
	*(u8 *)(r1 + 40) = r2
	r2 = *(u8 *)(r1 + 38)
	*(u8 *)(r1 + 39) = r2

	PREPARE_PACKET_FOOTER
