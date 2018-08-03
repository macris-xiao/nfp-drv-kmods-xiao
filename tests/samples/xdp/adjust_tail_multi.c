#include <errno.h>
#include <linux/bpf.h>

static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_tail;

int xdp_prog1(struct xdp_md *xdp) {
	/* Cut 30 bytes piece by piece */
	if (bpf_xdp_adjust_tail(xdp, -1))
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, -2))
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, -3))
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, -4))
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, -5))
		return XDP_ABORTED;

	/* Mix a bad one in */
	if (bpf_xdp_adjust_tail(xdp, 5) != -EINVAL)
		return XDP_ABORTED;

	if (bpf_xdp_adjust_tail(xdp, -15))
		return XDP_ABORTED;

	return XDP_PASS;
}
