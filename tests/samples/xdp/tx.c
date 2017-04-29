#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;
	unsigned int t;

	data2 =	data = (void *)(unsigned long)xdp->data;
	if (data + 60 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	t = *(unsigned *)(data + 0);
	*(unsigned *)(data + 0) = *(unsigned *)(data + 6);
	*(unsigned *)(data + 6) = t;

	t = *(unsigned short *)(data + 4);
	*(unsigned short *)(data + 4) = *(unsigned short *)(data + 10);
	*(unsigned short *)(data + 10) = t;

	/* Make ether type invalid */
	*(unsigned short *)(data + 12) = 0x3412;

	return XDP_TX;
}
