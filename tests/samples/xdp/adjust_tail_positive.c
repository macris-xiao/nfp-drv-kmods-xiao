#include <errno.h>
#include <linux/bpf.h>

static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_tail;

int xdp_prog1(struct xdp_md *xdp) {
	if (bpf_xdp_adjust_tail(xdp, 1) != -EINVAL)
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, 0x100) != -EINVAL)
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, 0xffff) != -EINVAL)
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, 0x10000) != -EINVAL)
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, 1U << 30) != -EINVAL)
		return XDP_ABORTED;
	/* Well, this one is kinda negative, but whatevs :) */
	if (bpf_xdp_adjust_tail(xdp, 1U << 31) != -EINVAL)
		return XDP_ABORTED;

	if (bpf_xdp_adjust_tail(xdp, xdp->data_end - xdp->data) != -EINVAL)
		return XDP_ABORTED;

	/* Well, non-negative? :) */
	if (bpf_xdp_adjust_tail(xdp, 0) != -EINVAL)
		return XDP_ABORTED;

	return XDP_PASS;
}
