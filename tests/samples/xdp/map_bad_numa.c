#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 4,
	.value_size = 8,
	.max_entries = 1,
	.map_flags = BPF_F_NUMA_NODE,
};

int prog()
{
	__u32 index = 0;
	long *value;

	value = bpf_map_lookup_elem(&arr, &index);
	if (!value)
		return XDP_DROP;

	return *value;
}
