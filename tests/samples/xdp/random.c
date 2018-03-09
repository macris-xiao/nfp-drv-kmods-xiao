#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};

int prog(struct xdp_md *xdp)
{
	unsigned char *data;
	__u32 index, val;
	__u32 *pkt_ptr;

	data = (void *)(unsigned long)xdp->data;
	if (data + 60 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	if (data[12] != 0x12 || data[13] != 0x22)
		return XDP_DROP;

	pkt_ptr = (__u32 *)(data + 14);

	index = *pkt_ptr;
	*pkt_ptr = 0;
	val = bpf_get_prandom_u32();

	if (bpf_map_update_elem(&arr, &index, &val, BPF_ANY))
		return XDP_DROP;

	return XDP_PASS;
}
