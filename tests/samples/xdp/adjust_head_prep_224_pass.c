#include <linux/bpf.h>

#define MAX_ADJUST	(256 - 32 /* struct xdp_frame */)

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned long long *data8;
	unsigned char *data, *data2;
	unsigned int i;

	if (bpf_xdp_adjust_head(xdp, -MAX_ADJUST))
		return XDP_ABORTED;

	data = (void *)(unsigned long)xdp->data;
	if (data + 64 + MAX_ADJUST >
	    (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data2 = data + MAX_ADJUST;

	for (i = 0; i < 12; i++)
		data[i] = data2[i];

	data[12] = 0x12;
	data[13] = 0x34;
	data[14] = 0;
	data[15] = 0;

	/* Clear with 8B accesses */
	data8 = (void *)&data[16];

#pragma clang loop unroll(full)
	for (i = 0; i < (MAX_ADJUST - 16) / sizeof(*data8); i++)
		data8[i] = 0;

	return XDP_PASS;
}
