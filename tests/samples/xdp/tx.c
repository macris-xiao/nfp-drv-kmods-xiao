#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;

	data2 =	data = (void *)(unsigned long)xdp->data;
	if (data + 64 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data2 += 6;

	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;
	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;
	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;

	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;
	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;
	*data2 ^= *data; *data ^= *data2; *data2 ^= *data; data++; data2++;

	/* Make ether type invalid */
	*data2 = 0x12; data2++;
	*data2 = 0x34; data2++;

	return XDP_TX;
}
