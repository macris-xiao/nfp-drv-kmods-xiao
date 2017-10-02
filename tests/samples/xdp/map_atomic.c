#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

int xdp_prog1()
{
	__u32 key = 0;
	long *value;

	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (!value)
		return XDP_DROP;

	__sync_fetch_and_add(value, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
