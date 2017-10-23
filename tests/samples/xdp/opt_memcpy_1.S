# Test memory copy on:
#
#   copy length > 32 & length <= 48
#   copy length is not 4-byte aligned.
#   copy elem width is byte.
#
# The test source comes from compile the following C code,
# but we want to cancel the instruction scheduling on the
# memcpy instruction sequences so it could trigger the JIT
# optimization as expected.
#
# int xdp_prog1(struct xdp_md *xdp) {
#	unsigned char *data;
#	unsigned int t;
#
#	data = (void *)(unsigned long)xdp->data;
#	if (data + 94 > (unsigned char *)(unsigned long)xdp->data_end)
#		return XDP_ABORTED;
#
#	if (*(unsigned short *)(data + 12) != 0x2212)
#		return XDP_DROP;
#
#	t = *(unsigned *)(data + 0);
#	*(unsigned *)(data + 0) = *(unsigned *)(data + 6);
#	*(unsigned *)(data + 6) = t;
#
#	t = *(unsigned short *)(data + 4);
#	*(unsigned short *)(data + 4) = *(unsigned short *)(data + 10);
#	*(unsigned short *)(data + 10) = t;
#
#	/* Make ether type invalid */
#	*(unsigned short *)(data + 12) = 0x3412;
#
#	__builtin_memcpy(data + 14, data + 47, 37);
#
#	return XDP_TX;
# }

	.include "opt_memcpy_common.x"
	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	PREPARE_PACKET_HEADER

	# sequence descending order (37-bytes)
	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, 0x880\] */
	/* CHECK-CODEGEN: .*immed\[\-\-, 0x980\] */
	/* CHECK-CODEGEN: .*mem\[read32_swap,.*0x2f,.*\], indirect_ref, ctx_swap */
	/* CHECK-CODEGEN: .*alu\[\$xfer_9, \-\-, B, \$xfer_9\] */
	/* CHECK-CODEGEN-NOT: .*immed\[\-\-, 0x780\] */
	/* CHECK-CODEGEN-NOT: .*mem\[write32_swap,.*0xe,.*\], indirect_ref */
	/* CHECK-CODEGEN: .*mem\[write32_swap,.*0xe,.*\], ctx_swap */
	/* CHECK-CODEGEN: .*mem\[write8_swap, \$xfer_8,.*0x2e,.*\], ctx_swap */
	r2 = *(u8 *)(r1 + 47)
	*(u8 *)(r1 + 14) = r2
	r2 = *(u8 *)(r1 + 48)
	*(u8 *)(r1 + 15) = r2
	r2 = *(u8 *)(r1 + 49)
	*(u8 *)(r1 + 16) = r2
	r2 = *(u8 *)(r1 + 50)
	*(u8 *)(r1 + 17) = r2
	r2 = *(u8 *)(r1 + 51)
	*(u8 *)(r1 + 18) = r2
	r2 = *(u8 *)(r1 + 52)
	*(u8 *)(r1 + 19) = r2
	r2 = *(u8 *)(r1 + 53)
	*(u8 *)(r1 + 20) = r2
	r2 = *(u8 *)(r1 + 54)
	*(u8 *)(r1 + 21) = r2
	r2 = *(u8 *)(r1 + 55)
	*(u8 *)(r1 + 22) = r2
	r2 = *(u8 *)(r1 + 56)
	*(u8 *)(r1 + 23) = r2
	r2 = *(u8 *)(r1 + 57)
	*(u8 *)(r1 + 24) = r2
	r2 = *(u8 *)(r1 + 58)
	*(u8 *)(r1 + 25) = r2
	r2 = *(u8 *)(r1 + 59)
	*(u8 *)(r1 + 26) = r2
	r2 = *(u8 *)(r1 + 60)
	*(u8 *)(r1 + 27) = r2
	r2 = *(u8 *)(r1 + 61)
	*(u8 *)(r1 + 28) = r2
	r2 = *(u8 *)(r1 + 62)
	*(u8 *)(r1 + 29) = r2
	r2 = *(u8 *)(r1 + 63)
	*(u8 *)(r1 + 30) = r2
	r2 = *(u8 *)(r1 + 64)
	*(u8 *)(r1 + 31) = r2
	r2 = *(u8 *)(r1 + 65)
	*(u8 *)(r1 + 32) = r2
	r2 = *(u8 *)(r1 + 66)
	*(u8 *)(r1 + 33) = r2
	r2 = *(u8 *)(r1 + 67)
	*(u8 *)(r1 + 34) = r2
	r2 = *(u8 *)(r1 + 68)
	*(u8 *)(r1 + 35) = r2
	r2 = *(u8 *)(r1 + 69)
	*(u8 *)(r1 + 36) = r2
	r2 = *(u8 *)(r1 + 70)
	*(u8 *)(r1 + 37) = r2
	r2 = *(u8 *)(r1 + 71)
	*(u8 *)(r1 + 38) = r2
	r2 = *(u8 *)(r1 + 72)
	*(u8 *)(r1 + 39) = r2
	r2 = *(u8 *)(r1 + 73)
	*(u8 *)(r1 + 40) = r2
	r2 = *(u8 *)(r1 + 74)
	*(u8 *)(r1 + 41) = r2
	r2 = *(u8 *)(r1 + 75)
	*(u8 *)(r1 + 42) = r2
	r2 = *(u8 *)(r1 + 76)
	*(u8 *)(r1 + 43) = r2
	r2 = *(u8 *)(r1 + 77)
	*(u8 *)(r1 + 44) = r2
	r2 = *(u8 *)(r1 + 78)
	*(u8 *)(r1 + 45) = r2
	r2 = *(u8 *)(r1 + 79)
	*(u8 *)(r1 + 46) = r2
	r2 = *(u8 *)(r1 + 80)
	*(u8 *)(r1 + 47) = r2
	r2 = *(u8 *)(r1 + 81)
	*(u8 *)(r1 + 48) = r2
	r2 = *(u8 *)(r1 + 82)
	*(u8 *)(r1 + 49) = r2
	r2 = *(u8 *)(r1 + 83)
	*(u8 *)(r1 + 50) = r2

	PREPARE_PACKET_FOOTER
