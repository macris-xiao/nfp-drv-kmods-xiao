#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 1,
	.value_size = 58,
	.max_entries = 1,
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
