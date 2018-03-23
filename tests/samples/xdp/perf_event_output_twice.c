#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") pa = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

int xdp_prog1(struct xdp_md *xdp)
{
	struct S {
		long pid;
		long cookie;
		long t[2];
	} data[2];

	data[0].pid = 0;
	data[0].cookie = 0x12345678;
	data[0].t[0] = 1;
	data[0].t[1] = 7;

	bpf_perf_event_output(xdp, &pa, 0x20ffffffffULL,
			      &data[0], sizeof(data[0]));

	data[1].pid = 0xaabbccdd;
	data[1].cookie = 0xeeff00112233;
	data[1].t[0] = 15;
	data[1].t[1] = 7ULL << 32;

	bpf_perf_event_output(xdp, &pa, 0x32ffffffffULL,
			      &data[1], sizeof(data[1]));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
