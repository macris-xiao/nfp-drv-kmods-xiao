#include <errno.h>
#include <linux/bpf.h>

static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_tail;

int xdp_prog1(struct xdp_md *xdp) {
	if (bpf_xdp_adjust_tail(xdp, 1))
		return XDP_ABORTED;
	if (bpf_xdp_adjust_tail(xdp, 0x100))
		return XDP_ABORTED;
	/* revert */
	if (bpf_xdp_adjust_tail(xdp, -0x101))
		return XDP_ABORTED;
	/* should not exceed frame_size, which is less than PAGE_SIZE */
	if (bpf_xdp_adjust_tail(xdp, 4096) != -EINVAL)
		return XDP_ABORTED;

	return XDP_PASS;
}
