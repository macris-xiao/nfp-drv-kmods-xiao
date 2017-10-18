
	r0 = 0
	*(u32 *)(r10 - 80) = r0

	.include "stack_write_unaligned.S"

	TEST 0x7766554433221100, 16
