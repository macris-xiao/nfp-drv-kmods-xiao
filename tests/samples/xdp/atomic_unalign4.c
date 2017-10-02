#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = 6,
	.max_entries = 1,
};

int xdp_prog1()
{
	unsigned char *data;
	__u32 key = 0;

	data = bpf_map_lookup_elem(&rxcnt, &key);
	if (!data)
		return XDP_DROP;

	data += 2;
	__sync_fetch_and_add((__u32 *)data, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
