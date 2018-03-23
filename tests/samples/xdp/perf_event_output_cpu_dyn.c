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
	int key = 0;
	__u64 len;

	len = xdp->data_end - xdp->data;

	bpf_perf_event_output(xdp, &pa, len << 32 | len, &key, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
