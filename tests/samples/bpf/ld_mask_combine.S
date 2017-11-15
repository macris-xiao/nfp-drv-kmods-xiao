# test nfp_bpf_opt_ld_mask pass

	.text
	.section	classifier,"ax",@progbits
	.globl	cls_entry
	.p2align	3
cls_entry:
	r6 = r1

	/* CHECK-CODEGEN-NOT: .*alu\[.*, AND, 0xff\].* */
	/* CHECK-CODEGEN-NOT: .*alu\[.*, AND, 0xffff\].* */

	# BPF_ABS
	r0 = *(u8 *)skb[32]
	r0 &= 0xff
	r0 = *(u16 *)skb[32]
	r0 &= 0xffff

	# BPF_IND
	r8 = 32
	r0 = *(u8 *)skb[r8]
	r0 &= 0xff
	r0 = *(u16 *)skb[r8]
	r0 &= 0xffff
	/* CHECK-CODEGEN: .*immed\[gprA_0, 0xffffffff\].* */
	r0 = 4294967295 ll
L0:
	exit
