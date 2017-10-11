#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data;
	unsigned short *data2;
	unsigned int *data4;
	unsigned long long *data8;

	data = (void *)(unsigned long)xdp->data;
	if (data + 64 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_DROP;

	data += 32;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data8[0] != 0x0807060504030201)
		return XDP_DROP;

	data8[0] = 0xffffffffffffffff;
	data4[0] = 0xeeeeeeee;
	data2[1] = 0xdddd;
	data[1] = data[8];

	/* unaligned */
	data += 9;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	data8[0] = 0xffffffffffffffff;
	data4[0] = 0xeeeeeeee;
	data2[1] = 0xdddd;
	data[1] = data[8];

	return XDP_PASS;
}
