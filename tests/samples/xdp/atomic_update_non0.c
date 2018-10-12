#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

int xdp_prog1()
{
	__u64 nonzeroval = 3;
	__u32 key = 0;
	__u64 *value;

	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (!value)
		bpf_map_update_elem(&rxcnt, &key, &nonzeroval, BPF_ANY);
	else
		__sync_fetch_and_add(value, 1);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
