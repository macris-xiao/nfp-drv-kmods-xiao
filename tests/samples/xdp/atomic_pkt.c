#include <linux/bpf.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

int xdp_prog1(struct xdp_md *xdp)
{
	unsigned char *data;
	long *ptr;

	data = (void *)(unsigned long)xdp->data;
	if (data + 60 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	ptr = (void *)(data + 40);
	__sync_fetch_and_add(ptr, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
