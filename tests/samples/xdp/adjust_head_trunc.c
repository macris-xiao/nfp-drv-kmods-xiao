#include <linux/bpf.h>

static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
        (void *) BPF_FUNC_xdp_adjust_head;

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;

	data2 =	data = (void *)(unsigned long)xdp->data;
	if (data + 64 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	data += 13;
	data2 += 11;

	*data-- = *data2--;
	*data-- = *data2--;
	*data-- = *data2--;

	*data-- = *data2--;
	*data-- = *data2--;
	*data-- = *data2--;

	*data-- = *data2--;
	*data-- = *data2--;
	*data-- = *data2--;

	*data-- = *data2--;
	*data-- = *data2--;
	*data-- = *data2--;

	if (bpf_xdp_adjust_head(xdp, 2))
		return XDP_ABORTED;

	data2 = data = (void *)(unsigned long)xdp->data;
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
	*data2++ = 0x12;
	*data2++ = 0x34;

	return XDP_TX;
}
