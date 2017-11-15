# test nfp_bpf_opt_ld_shift pass

	.text
	.section	classifier,"ax",@progbits
	.globl	cls_entry
	.p2align	3
cls_entry:
	r6 = r1

	/* CHECK-CODEGEN-NOT: .*alu\[gprA_1,.*, B, gprB_0\].* */

	# BPF_ABS
	r0 = *(u32 *)skb[32]
	r0 <<= 32
	r0 >>= 32

	# BPF_IND
	r8 = 32
	r0 = *(u32 *)skb[r8]
	r0 <<= 32
	r0 >>= 32

	/* CHECK-CODEGEN: .*immed\[gprA_0, 0xffffffff\].* */
	r0 = 4294967295 ll
L0:
	exit
