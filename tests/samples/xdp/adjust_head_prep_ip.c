#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;
	unsigned short *data16;
	unsigned short tl;

	data = (void *)(unsigned long)xdp->data;
	if (data + 20 + 14 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	if (*(data + 12) != 0x8 || *(data + 13) != 0)
		return XDP_PASS;

	data16 = (void *)data + 16;
	tl = *data16;
	tl = ((tl & 0xff) << 8) | (tl >> 8); /* Byte swap */

	if (bpf_xdp_adjust_head(xdp, -20))
		return XDP_ABORTED;

	data = (void *)(unsigned long)xdp->data;
	if (data + 64 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data2 = data + 20;

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

	/* IP header */
	*data++ = 0x45;
	*data++ = 0x00;

	tl += 20;
	*data++ = tl >> 8;
	*data++ = tl & 0xff;

	*data++ = 0xca;
	*data++ = 0xfe;

	*data++ = 0x40; /* Don't fragment */
	*data++ = 0;

	*data++ = 17;

	*data++ = 4;

	*data++ = 0x88;
	*data++ = 0xe9 - (tl & 0xff);

	*data++ = 10;
	*data++ = 8;
	*data++ = 1;
	*data++ = 2;

	*data++ = 10;
	*data++ = 8;
	*data++ = 1;
	*data++ = 1;

	return XDP_PASS;
}
