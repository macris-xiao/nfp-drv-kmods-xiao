# test nfp_bpf_opt_ld_shift pass

	.text
	.section	classifier,"ax",@progbits
	.globl	cls_entry
	.p2align	3
cls_entry:
	r6 = r1

	/* CHECK-CODEGEN-TIMES-4: .*alu\[gprA_1,.*, B, gprB_0\].* */

	# BPF_ABS
	r0 = *(u32 *)skb[32]
	r0 <<= 32
	r0 >>= 32

	r0 = *(u16 *)skb[32]
	r7 = r0

	# jump to head won't stop the combination.
	if r7 != 0 goto L1
	r0 = 1
L1:
	r0 = *(u32 *)skb[32]
	r0 <<= 32
	r0 >>= 32

	# jump to middle will stop the combination.
	if r7 != 0 goto L2
	r0 = *(u32 *)skb[32]
L2:
	r0 <<= 32
	r0 >>= 32

	if r7 != 0 goto L3
	r0 = *(u32 *)skb[32]
	r0 <<= 32
L3:
	r0 >>= 32


	# BPF_IND
	r8 = 32
	r0 = *(u32 *)skb[r8]
	r0 <<= 32
	r0 >>= 32

	# jump to head won't stop the combination.
	if r7 != 0 goto L4
	r0 = 1
L4:
	r0 = *(u32 *)skb[r8]
	r0 <<= 32
	r0 >>= 32

	# jump to middle will stop the combination.
	if r7 != 0 goto L5
	r0 = *(u32 *)skb[r8]
L5:
	r0 <<= 32
	r0 >>= 32

	if r7 != 0 goto L6
	r0 = *(u32 *)skb[r8]
	r0 <<= 32
L6:
	r0 >>= 32

	/* CHECK-CODEGEN: .*immed\[gprA_0, 0xffffffff\].* */
	r0 = 4294967295 ll
L0:
	exit
