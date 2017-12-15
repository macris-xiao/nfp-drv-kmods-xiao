#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

#define A(_name_)					\
	struct bpf_map_def SEC("maps") _name_ = {	\
		.type = BPF_MAP_TYPE_HASH,		\
		.key_size = sizeof(__u32),		\
		.value_size = sizeof(long),		\
		.max_entries = 2,			\
	}

A(arr0);
A(arr1);
A(arr2);
A(arr3);
A(arr4);
A(arr5);
A(arr6);
A(arr7);
A(arr8);
A(arr9);
A(arrA);
A(arrB);
A(arrC);
A(arrD);
A(arrE);
A(arrF);

int prog()
{
	__u32 index = 0;
	long *value;

	value = bpf_map_lookup_elem(&arr0, &index);
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
	value = bpf_map_lookup_elem(&arr5, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arr6, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arr7, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arr8, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arr9, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrA, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrB, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrC, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrD, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrE, &index);
	if (!value)
		return XDP_DROP;
	value = bpf_map_lookup_elem(&arrF, &index);
	if (!value)
		return XDP_DROP;

	return *value;
}
