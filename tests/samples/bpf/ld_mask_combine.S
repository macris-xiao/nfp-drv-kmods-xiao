# test nfp_bpf_opt_ld_mask pass

	.text
	.section	classifier,"ax",@progbits
	.globl	cls_entry
	.p2align	3
cls_entry:
	r6 = r1

	# BPF_ABS
	r0 = *(u8 *)skb[32]
	r0 &= 0xff
	r0 = *(u16 *)skb[32]
	r0 &= 0xffff

	r0 = *(u16 *)skb[32]
	r7 = r0

	# jump to head won't stop the combination.
	if r7 != 0 goto L1
        r0 = 1
L1:
	r0 = *(u8 *)skb[32]
	r0 &= 0xff

	# jump to middle will stop the combination.
	if r7 != 0 goto L2
	r0 = *(u16 *)skb[32]
L2:
	/* CHECK-CODEGEN-TIMES-1: .*immed\[gpr.*, 0xffff\].* */
	r0 &= 0xffff


	# BPF_IND
	r8 = 32
	r0 = *(u8 *)skb[r8]
	r0 &= 0xff
	r0 = *(u16 *)skb[r8]
	r0 &= 0xffff

	if r7 != 0 goto L3
	r0 = 1
L3:
	r0 = *(u16 *)skb[r8]
	r0 &= 0xffff

	if r7 != 0 goto L4
	r0 = *(u8 *)skb[r8]
L4:
	/* CHECK-CODEGEN-TIMES-1: .*alu\[.*, AND, 0xff\].* */
	r0 &= 0xff

	/* CHECK-CODEGEN: .*immed\[gprA_0, 0xffffffff\].* */
	r0 = 4294967295 ll
L0:
	exit
