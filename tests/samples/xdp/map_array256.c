#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

int prog(struct xdp_md *xdp)
{
	unsigned char *data;
	__u32 index;
	long *value;

	data = (void *)(unsigned long)xdp->data;
	if (data + 32 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	/* Look up the byte after ethtype */
	data += 14;
	index = *data;

	value = bpf_map_lookup_elem(&arr, &index);
	if (!value)
		return XDP_DROP;

	return *value;
}
