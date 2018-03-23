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
	__u64 keys[32];
	__u64 len;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < 32; i++)
		keys[i] = 0;

	len = xdp->data_end - xdp->data;

	bpf_perf_event_output(xdp, &pa, len << 32 | 0xffffffffULL,
			      &keys, sizeof(keys));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
