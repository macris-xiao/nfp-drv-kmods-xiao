#include <linux/bpf.h>

static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_tail;

int xdp_prog1(struct xdp_md *xdp) {
	if (bpf_xdp_adjust_tail(xdp, xdp->data - xdp->data_end + 14))
		return XDP_ABORTED;

	return XDP_PASS;
}
