# test BPF_NEG

	.text
	.globl	xdp_prog1
	.p2align	3
xdp_prog1:
	r0 = 0
	r2 = *(u32 *)(r1 + 4)
	r1 = *(u32 *)(r1 + 0)
	r3 = r1
	r3 += 60
	if r3 > r2 goto LBB0_2
	r0 = 1
	r2 = *(u16 *)(r1 + 12)
	if r2 != 8722 goto LBB0_2

	# BPF_ALU | BPF_NEG
	w2 = -w2
	*(u64 *)(r1 + 14) = r2

	# BPF_ALU64 | BPF_NEG
	r2 = *(u64 *)(r1 + 22)
	r2 = -r2
	*(u64 *)(r1 + 22) = r2

	r2 = *(u32 *)(r1 + 0)
	r3 = *(u32 *)(r1 + 6)
	*(u32 *)(r1 + 0) = r3
	*(u32 *)(r1 + 6) = r2
	r2 = *(u16 *)(r1 + 4)
	r3 = *(u16 *)(r1 + 10)
	*(u16 *)(r1 + 4) = r3
	*(u16 *)(r1 + 10) = r2
	r0 = 3
LBB0_2:
	exit
