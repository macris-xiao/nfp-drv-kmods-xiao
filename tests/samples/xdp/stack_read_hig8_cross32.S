
	r0 = 0
	// If unaligned access is ever added again, the stack size should
	// be bumped to 104, today we can only test one word below, one above
	// for the zero-offset case
	*(u32 *)(r10 - 100) = r0

	.include "stack_read.S"

	TEST 0x7766554433221100, 0xffeeddccbbaa9988, 64
