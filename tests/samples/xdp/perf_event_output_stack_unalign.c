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
	} data;

	data.pid = 0;
	data.cookie = 0x12345678;
	data.t[0] = 1;
	data.t[1] = 7;

	bpf_perf_event_output(xdp, &pa, 0xffffffffULL, (char *)&data + 1, 4);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
