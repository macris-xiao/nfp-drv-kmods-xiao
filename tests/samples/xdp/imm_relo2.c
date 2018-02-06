#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

int prog()
{
	volatile long ret;
	__u32 index = 0;
	long *value;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < 256; i++)
		ret = XDP_ABORTED;

	value = bpf_map_lookup_elem(&arr, &index);
	if (value)
		return XDP_TX;

#pragma clang loop unroll(full)
	for (i = 0; i < 311; i++)
		ret = XDP_ABORTED;

	value = bpf_map_lookup_elem(&arr, &index);
	ret = XDP_PASS;
	if (ret != XDP_PASS) {
#pragma clang loop unroll(full)
		for (i = 0; i < 256; i++)
			ret = XDP_ABORTED;
	}
	if (value)
		return XDP_TX;

	return ret;
}
