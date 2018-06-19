// We use assembly file as we don't want to compiler instruction scheduling
// reorder some insn sequences that we want to feed into our driver eBPF JIT
// compiler.
//
// The C source file for this test is the following except the NOTEed change
// in the last hunk of the assembly.
//
// #include <linux/bpf.h>
// #include <linux/errno.h>
// #include "../bpf/bpf_api.h"
// #include "../bpf/bpf_helpers.h"
//
// struct bpf_map_def SEC("maps") htab = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(__u32),
// 	.value_size = 40,
// 	.max_entries = 1,
// };
//
// int prog(struct xdp_md *xdp)
// {
// 	unsigned char *data;
// 	__u32 index = 0;
// 	__u32 *pkt_ptr;
// 	char *value;
//
// 	data = (void *)(unsigned long)xdp->data;
// 	if (data + 88 > (unsigned char *)(unsigned long)xdp->data_end)
// 		return XDP_ABORTED;
//
// 	value = bpf_map_lookup_elem(&htab, &index);
// 	if (!value)
// 		return XDP_DROP;
//
// 	__builtin_memcpy(data + 18, value, 7);
// 	__builtin_memcpy(data + 32, value, 14);
// 	__builtin_memcpy(data + 48, value, 33);
//
// 	if (bpf_map_delete_elem(&htab, &index))
// 		return XDP_DROP;
//
// 	pkt_ptr = (__u32 *)(data + 14);
// 	*pkt_ptr = 0;
// 	return XDP_PASS;
// }
	.text
	.globl	prog
	.p2align	3
prog:
	r2 = 0
	*(u32 *)(r10 - 4) = r2
	r3 = *(u32 *)(r1 + 4)
	r6 = *(u32 *)(r1 + 0)
	r1 = r6
	r1 += 88
	if r1 > r3 goto LBB0_3
	r2 = r10
	r2 += -4
	r1 = htab ll
	call 1
	r2 = 1
	if r0 == 0 goto LBB0_3
	// memcpy sequence 1
	/* CHECK-CODEGEN: .*mem\[write8_swap, \$xfer_0,.*0x12,.*\], ctx_swap.* */
	r1 = *(u8 *)(r0 + 6)
	*(u8 *)(r6 + 24) = r1
	r1 = *(u8 *)(r0 + 5)
	*(u8 *)(r6 + 23) = r1
	r1 = *(u8 *)(r0 + 4)
	*(u8 *)(r6 + 22) = r1
	r1 = *(u8 *)(r0 + 3)
	*(u8 *)(r6 + 21) = r1
	r1 = *(u8 *)(r0 + 2)
	*(u8 *)(r6 + 20) = r1
	r1 = *(u8 *)(r0 + 1)
	*(u8 *)(r6 + 19) = r1
	r1 = *(u8 *)(r0 + 0)
	*(u8 *)(r6 + 18) = r1
	// memcpy sequence 2
	/* CHECK-CODEGEN: .*mem\[write8_swap, \$xfer_0,.*0x20,.*\], indirect_ref.* */
	r1 = *(u8 *)(r0 + 13)
	*(u8 *)(r6 + 45) = r1
	r1 = *(u8 *)(r0 + 12)
	*(u8 *)(r6 + 44) = r1
	r1 = *(u8 *)(r0 + 11)
	*(u8 *)(r6 + 43) = r1
	r1 = *(u8 *)(r0 + 10)
	*(u8 *)(r6 + 42) = r1
	r1 = *(u8 *)(r0 + 9)
	*(u8 *)(r6 + 41) = r1
	r1 = *(u8 *)(r0 + 8)
	*(u8 *)(r6 + 40) = r1
	r1 = *(u8 *)(r0 + 7)
	*(u8 *)(r6 + 39) = r1
	r1 = *(u8 *)(r0 + 6)
	*(u8 *)(r6 + 38) = r1
	r1 = *(u8 *)(r0 + 5)
	*(u8 *)(r6 + 37) = r1
	r1 = *(u8 *)(r0 + 4)
	*(u8 *)(r6 + 36) = r1
	r1 = *(u8 *)(r0 + 3)
	*(u8 *)(r6 + 35) = r1
	r1 = *(u8 *)(r0 + 2)
	*(u8 *)(r6 + 34) = r1
	r1 = *(u8 *)(r0 + 1)
	*(u8 *)(r6 + 33) = r1
	r1 = *(u8 *)(r0 + 0)
	*(u8 *)(r6 + 32) = r1
	// memcpy sequence 3
	/* CHECK-CODEGEN: .*mem\[write32_swap, \$xfer_0,.*0x30, 8\], ctx_swap.* */
	/* CHECK-CODEGEN: .*mem\[write8_swap, \$xfer_8,.*0x50, 1\], ctx_swap.* */
	// NOTE: change copy source to r3 to test JIT for non-zero register.
	r3 = r0
	r1 = *(u8 *)(r3 + 32)
	*(u8 *)(r6 + 80) = r1
	r1 = *(u8 *)(r3 + 31)
	*(u8 *)(r6 + 79) = r1
	r1 = *(u8 *)(r3 + 30)
	*(u8 *)(r6 + 78) = r1
	r1 = *(u8 *)(r3 + 29)
	*(u8 *)(r6 + 77) = r1
	r1 = *(u8 *)(r3 + 28)
	*(u8 *)(r6 + 76) = r1
	r1 = *(u8 *)(r3 + 27)
	*(u8 *)(r6 + 75) = r1
	r1 = *(u8 *)(r3 + 26)
	*(u8 *)(r6 + 74) = r1
	r1 = *(u8 *)(r3 + 25)
	*(u8 *)(r6 + 73) = r1
	r1 = *(u8 *)(r3 + 24)
	*(u8 *)(r6 + 72) = r1
	r1 = *(u8 *)(r3 + 23)
	*(u8 *)(r6 + 71) = r1
	r1 = *(u8 *)(r3 + 22)
	*(u8 *)(r6 + 70) = r1
	r1 = *(u8 *)(r3 + 21)
	*(u8 *)(r6 + 69) = r1
	r1 = *(u8 *)(r3 + 20)
	*(u8 *)(r6 + 68) = r1
	r1 = *(u8 *)(r3 + 19)
	*(u8 *)(r6 + 67) = r1
	r1 = *(u8 *)(r3 + 18)
	*(u8 *)(r6 + 66) = r1
	r1 = *(u8 *)(r3 + 17)
	*(u8 *)(r6 + 65) = r1
	r1 = *(u8 *)(r3 + 16)
	*(u8 *)(r6 + 64) = r1
	r1 = *(u8 *)(r3 + 15)
	*(u8 *)(r6 + 63) = r1
	r1 = *(u8 *)(r3 + 14)
	*(u8 *)(r6 + 62) = r1
	r1 = *(u8 *)(r3 + 13)
	*(u8 *)(r6 + 61) = r1
	r1 = *(u8 *)(r3 + 12)
	*(u8 *)(r6 + 60) = r1
	r1 = *(u8 *)(r3 + 11)
	*(u8 *)(r6 + 59) = r1
	r1 = *(u8 *)(r3 + 10)
	*(u8 *)(r6 + 58) = r1
	r1 = *(u8 *)(r3 + 9)
	*(u8 *)(r6 + 57) = r1
	r1 = *(u8 *)(r3 + 8)
	*(u8 *)(r6 + 56) = r1
	r1 = *(u8 *)(r3 + 7)
	*(u8 *)(r6 + 55) = r1
	r1 = *(u8 *)(r3 + 6)
	*(u8 *)(r6 + 54) = r1
	r1 = *(u8 *)(r3 + 5)
	*(u8 *)(r6 + 53) = r1
	r1 = *(u8 *)(r3 + 4)
	*(u8 *)(r6 + 52) = r1
	r1 = *(u8 *)(r3 + 3)
	*(u8 *)(r6 + 51) = r1
	r1 = *(u8 *)(r3 + 2)
	*(u8 *)(r6 + 50) = r1
	r1 = *(u8 *)(r3 + 1)
	*(u8 *)(r6 + 49) = r1
	r1 = *(u8 *)(r3 + 0)
	*(u8 *)(r6 + 48) = r1
	r1 = 0
	*(u32 *)(r6 + 14) = r1
	r2 = 2
LBB0_3:
	r0 = r2
	exit

	.section	maps,"aw",@progbits
	.globl	htab
	.p2align	2
htab:
	.long	1
	.long	4
	.long	40
	.long	1
	.long	0
	.long	0
