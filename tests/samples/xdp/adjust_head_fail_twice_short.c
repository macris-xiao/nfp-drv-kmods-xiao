#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	if (bpf_xdp_adjust_head(xdp, 256))
		return XDP_ABORTED;

	if (bpf_xdp_adjust_head(xdp, 256))
		return XDP_ABORTED;

	return XDP_PASS;
}
