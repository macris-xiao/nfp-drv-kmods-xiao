#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;

	data2 =	data = (void *)(unsigned long)xdp->data;
	if (data + 64 + 14 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data = data + 64;

	*data++ = *data2++;
	*data++ = *data2++;
	*data++ = *data2++;

	*data++ = *data2++;
	*data++ = *data2++;
	*data++ = *data2++;

	*data++ = *data2++;
	*data++ = *data2++;
	*data++ = *data2++;

	*data++ = *data2++;
	*data++ = *data2++;
	*data++ = *data2++;

	*data++ = 0x12;
	*data++ = 0x34;

	if (bpf_xdp_adjust_head(xdp, 64))
		return XDP_ABORTED;

	return XDP_PASS;
}
