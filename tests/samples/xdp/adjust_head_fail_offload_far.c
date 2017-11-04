#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data;

	data = (void *)(unsigned long)xdp->data;
	if (data + 256 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	__builtin_memcpy(data + 113, data, 14);

	if (bpf_xdp_adjust_head(xdp, 113))
		return XDP_ABORTED;

	return XDP_PASS;
}
