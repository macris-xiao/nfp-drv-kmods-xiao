#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned long long *data8;
	unsigned char *data, *data2;

	if (bpf_xdp_adjust_head(xdp, -256))
		return XDP_ABORTED;

	data = (void *)(unsigned long)xdp->data;
	if (data + 64 + 256 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data2 = data + 256;

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
	*data++ = 0;

	*data++ = 0;

	/* Clear with 8B accesses */
	data8 = (void *)data;

	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;
	*data8++ = 0;

	return XDP_PASS;
}
