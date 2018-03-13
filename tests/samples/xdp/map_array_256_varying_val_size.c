#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct mapval2 {
	__u32 value0;
	__u32 value1;
};

struct mapval4 {
	__u32 value0;
	__u32 value1;
	__u32 value2;
	__u32 value3;
};

struct mapval8 {
	__u32 value0;
	__u32 value1;
	__u32 value2;
	__u32 value3;
	__u32 value4;
	__u32 value5;
	__u32 value6;
	__u32 value7;
};

struct mapval12 {
	__u32 value0;
	__u32 value1;
	__u32 value2;
	__u32 value3;
	__u32 value4;
	__u32 value5;
	__u32 value6;
	__u32 value7;
	__u32 value8;
	__u32 value9;
	__u32 valueA;
	__u32 valueB;
};

struct mapval14 {
	__u32 value0;
	__u32 value1;
	__u32 value2;
	__u32 value3;
	__u32 value4;
	__u32 value5;
	__u32 value6;
	__u32 value7;
	__u32 value8;
	__u32 value9;
	__u32 valueA;
	__u32 valueB;
	__u32 valueC;
	__u32 valueD;
};

struct bpf_map_def SEC("maps") arr = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct mapval2),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") arr1 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct mapval4),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") arr2 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct mapval8),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") arr3 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct mapval12),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") arr4 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct mapval14),
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

	value = bpf_map_lookup_elem(&arr1, &index);
	if (!value)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&arr2, &index);
	if (!value)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&arr3, &index);
	if (!value)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&arr4, &index);
	if (!value)
		return XDP_DROP;

	return *value;
}
