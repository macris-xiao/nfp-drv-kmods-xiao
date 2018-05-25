#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

int prog()
{
	__u32 val =0, val_prev = 0;

	#pragma clang loop unroll(full)
	for (__u32 i = 0; i < 128; i++){
		val = bpf_get_prandom_u32();
		if (val == val_prev)
			return XDP_DROP;
		val_prev = val;
	}
	return XDP_TX;
}
