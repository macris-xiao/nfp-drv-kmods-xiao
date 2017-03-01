#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;

	data = (void *)(unsigned long)xdp->data;
	if (data + 20 + 14 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	/* Skip non-IP */
	if (*(data + 12) != 0x8 || *(data + 13) != 0)
		return XDP_PASS;

	/* Skip non-IPIP */
	if (*(data + 14 + 9) != 0x4)
		return XDP_PASS;

	data2 = data;
	data = data + 20;

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

	/* Ethertype */
	*data++ = *data2++;
	*data++ = *data2++;

	if (bpf_xdp_adjust_head(xdp, 20))
		return XDP_ABORTED;

	return XDP_PASS;
}
