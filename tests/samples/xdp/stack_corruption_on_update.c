#include <linux/bpf.h>
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 16,
};

enum {
	V1 = 0x100,
	V2,
	V3,
};

int xdp_prog1()
{
	__u32 keys[4];

	/* Using an initializer sometimes makes LLVM use relos for const data */
	keys[0] = V1;
	keys[1] = V2;
	keys[2] = V3;

	/* Update key0 to key2 (bottom to top) */
	bpf_map_update_elem(&map, &keys[0], &keys[2], 0);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	/* Update key2 to key0 (top to bottom) */
	bpf_map_update_elem(&map, &keys[2], &keys[0], 0);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	/* Update key0 to key1 (bottom to mid) */
	bpf_map_update_elem(&map, &keys[0], &keys[1], 0);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	/* Update key0 to key0 (bottom to bottom) */
	bpf_map_update_elem(&map, &keys[0], &keys[0], 0);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
