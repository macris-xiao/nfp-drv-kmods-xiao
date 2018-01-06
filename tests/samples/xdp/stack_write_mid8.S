
	r0 = 0
	*(u32 *)(r10 - 48) = r0

	.include "stack_write.S"

	TEST 0x7766554433221100, 64
