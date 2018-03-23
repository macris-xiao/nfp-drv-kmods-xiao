#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") pa = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

int xdp_prog1(struct xdp_md *xdp)
{
	__u32 key = 0;
	char *value;

	value = bpf_map_lookup_elem(&arr, &key);
	if (!value)
		return XDP_DROP;

	bpf_perf_event_output(xdp, &pa, 0xffffffffULL, value + 1, 2);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
