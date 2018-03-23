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
	__u32 data = 0x01020304;

	bpf_perf_event_output(xdp, &pa, 0x1ffffffffULL, &data, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
