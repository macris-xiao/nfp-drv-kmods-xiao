#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

int xdp_prog1()
{
	volatile __u32 key = 0;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < 2000; i++)
		if (key)
			return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
