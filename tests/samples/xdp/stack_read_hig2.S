
	r0 = 0
	*(u32 *)(r10 - 80) = r0

	.include "stack_read.S"

	TEST 0x7766554433221100, 0xffeeddccbbaa9988, 16
