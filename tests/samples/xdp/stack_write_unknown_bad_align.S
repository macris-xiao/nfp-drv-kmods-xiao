	r0 = 0
	r1 = 0
	r9 = r10

	;; need more stack to be inited
	*(u64 *)(r10 - 24) = r0
	;; remove and add because we want the jump to have wrong off
	;; verifier checks non-fall-through first
	r9 += -2

	if r0 != r1 goto skip_add
	r9 += 2
skip_add:

	.include "stack_write_unaligned.S"

	TEST 0x7766554433221100, 64, r9
