#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") htab = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 6,
	.value_size = sizeof(long),
	.max_entries = (1 << 18),
};

int prog(struct xdp_md *xdp)
{
	unsigned char key[6];
	unsigned char *data;
	long *value;

	data = (void *)(unsigned long)xdp->data;
	if (data + 32 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	/* Look up 6 bytes after ethtype */
	data += 14;
	memcpy(key, data, 6);

	value = bpf_map_lookup_elem(&htab, key);
	if (!value)
		return XDP_DROP;

	return *value;
}
