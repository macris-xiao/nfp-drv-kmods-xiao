.include "xdp.S"

main:
	r2 = 0x0102030405060708
	call dump_r2
	exit

dump_r2:
	*(u64 *)(r10 - 8) = r2
	r4 = r10
	r4 += -8
	r2 = perf ll
	r3 = 0x1ffffffff ll
	r5 = 8
	call 25		// bpf_perf_event_output(context, map, flags, data, size);
	r0 = XDP_PASS
	/* CHECK-CODEGEN: .*rtn\[gprA_\d\].* */
	exit

// struct bpf_map_def SEC("maps") pa = {
//         .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//         .key_size = sizeof(int),
//         .value_size = sizeof(int),
//         .max_entries = 64,
// };
	.section	maps,"aw",@progbits
	.globl		perf
	.p2align	2
perf:
	.long 4
	.long 4
	.long 4
	.long 40
	.long 0
	.long 0

// char _license[] SEC("license") = "GPL";
	.section	license,"aw",@progbits
	.globl		_license
_license:
	.asciz		"GPL"
