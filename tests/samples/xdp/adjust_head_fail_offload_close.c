#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data;

	if (bpf_xdp_adjust_head(xdp, -94))
		return XDP_ABORTED;

	data = (void *)(unsigned long)xdp->data;
	if (data + 256 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	__builtin_memcpy(data, data + 94, 14);
	__builtin_memset(data + 14, 0, 80);

	return XDP_PASS;
}
