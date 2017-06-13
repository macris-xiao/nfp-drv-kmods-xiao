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

	if (data[0] != 0x01 || data[1] != 0x02 ||
	    data[2] != 0x03 || data[3] != 0x04)
		return XDP_DROP;

	if (data2[0] != 0x0201 || data2[1] != 0x0403)
		return XDP_DROP;

	if (data4[0] != 0x04030201)
		return XDP_DROP;

	if (data8[0] != 0x0807060504030201)
		return XDP_DROP;

	data += 1;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data[0] != 0x02 || data[1] != 0x03 ||
	    data[2] != 0x04 || data[3] != 0x05)
		return XDP_DROP;

	if (data2[0] != 0x0302 || data2[1] != 0x0504)
		return XDP_DROP;

	if (data4[0] != 0x05040302)
		return XDP_DROP;

	if (data8[0] != 0xbb08070605040302)
		return XDP_DROP;

	data -= 2;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data[0] != 0xaa || data[1] != 0x01 ||
	    data[2] != 0x02 || data[3] != 0x03)
		return XDP_DROP;

	if (data2[0] != 0x01aa || data2[1] != 0x0302)
		return XDP_DROP;

	if (data4[0] != 0x030201aa)
		return XDP_DROP;

	if (data8[0] != 0x07060504030201aa)
		return XDP_DROP;

	return XDP_PASS;
}
