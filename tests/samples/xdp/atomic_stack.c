#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

int xdp_prog1()
{
	long value = 0;

	__sync_fetch_and_add(&value, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
