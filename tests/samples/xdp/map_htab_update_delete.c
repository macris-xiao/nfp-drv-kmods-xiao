#include <linux/bpf.h>
#include <linux/errno.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 100,
};

int prog(struct xdp_md *xdp)
{
	unsigned char *data;
	__u32 *pkt_ptr;
	__u32 index;
	long val;
	long *value;

	data = (void *)(unsigned long)xdp->data;
	if (data + 60 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	pkt_ptr = (__u32 *)(data + 14);
	val = index = *pkt_ptr;

	/* assume starting empty */
	value = bpf_map_lookup_elem(&arr, &index);
	if (value)
		return XDP_ABORTED;

	if (bpf_map_update_elem(&arr, &index, &val, BPF_EXIST) != -ENOENT)
		return XDP_DROP;
	if (bpf_map_update_elem(&arr, &index, &val, BPF_ANY))
		return XDP_DROP;
	if (bpf_map_update_elem(&arr, &index, &val, BPF_NOEXIST) != -EEXIST)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&arr, &index);
	if (!value)
		return XDP_DROP;
	if (*value != index)
		return XDP_ABORTED;

	if (bpf_map_delete_elem(&arr, &index))
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arr, &index);
	if (value)
		return XDP_DROP;
	if (bpf_map_delete_elem(&arr, &index) != -ENOENT)
		return XDP_DROP;

	*pkt_ptr = 0;
	return XDP_PASS;
}
