#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps") arr2 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

int prog(struct xdp_md *xdp)
{
	struct bpf_map_def *map;
	unsigned char *data;
	__u32 index;
	long *value;

	data = (void *)(unsigned long)xdp->data;
	if (data + 32 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	/* Look up the byte after ethtype */
	data += 14;
	index = *data;

	map = data[1] ? &arr2 : &arr1;

	value = bpf_map_lookup_elem(map, &index);
	if (!value)
		return XDP_DROP;

	return *value;
}
