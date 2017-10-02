#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

int xdp_prog1(struct xdp_md *xdp)
{
	unsigned char *data;
	unsigned long *ptr;
	__u32 key = 0;
	long *value;

	data = (void *)(unsigned long)xdp->data;
	if (data + 60 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	if (data[12] != 0x12 || data[13] != 0x22)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (!value)
		return XDP_DROP;

	ptr = (void *)(data + 40);
	__sync_fetch_and_add(value, *ptr >> 8);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
