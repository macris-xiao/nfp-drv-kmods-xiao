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

	/* Single lookup from base of stack (LM0 may get corrupted) */
	bpf_map_lookup_elem(&map, &keys[0]);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	/* All lookups */
	bpf_map_lookup_elem(&map, &keys[0]);
	bpf_map_lookup_elem(&map, &keys[1]);
	bpf_map_lookup_elem(&map, &keys[2]);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	/* All lookups - reverse */
	bpf_map_lookup_elem(&map, &keys[2]);
	bpf_map_lookup_elem(&map, &keys[1]);
	bpf_map_lookup_elem(&map, &keys[0]);

	if (keys[0] != V1 || keys[1] != V2 || keys[2] != V3)
		return XDP_DROP;

	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
