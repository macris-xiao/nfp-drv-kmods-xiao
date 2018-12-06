	// save ctx
	r8 = r1

	// r1 is already ctx
	r2 = 0  // offset
	call 44 // adjust head

	// second call which will never happen
	r1 = r8
	r2 = 0  // offset
	if r2 == 0 goto skip_second_call
	call 44 // adjust head
skip_second_call:

	// clear top bits LLVM style, I know.
	r0 <<= 32
	r0 >>= 32

	if r0 == 0 goto good
	r0 = 0
	exit

good:
	r0 = 2
	exit
