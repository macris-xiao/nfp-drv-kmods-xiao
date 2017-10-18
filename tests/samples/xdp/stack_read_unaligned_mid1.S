
	r0 = 0
	*(u32 *)(r10 - 48) = r0

	.include "stack_read_unaligned.S"

	TEST 0x7766554433221100, 0xffeeddccbbaa9988, u8, 0xff
