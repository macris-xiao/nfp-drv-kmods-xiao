/* memcpy/memmove test from C. */
#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp)
{
	unsigned short *short_data;
	unsigned int *int_data;
	unsigned char *data;
	unsigned int t;

	data = (void *)(unsigned long)xdp->data;
	if (data + 94 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	if (*(unsigned short *)(data + 12) != 0x2212)
		return XDP_DROP;

	t = *(unsigned int *)(data + 0);
	*(unsigned int *)(data + 0) = *(unsigned int *)(data + 6);
	*(unsigned int *)(data + 6) = t;

	t = *(unsigned short *)(data + 4);
	*(unsigned short *)(data + 4) = *(unsigned short *)(data + 10);
	*(unsigned short *)(data + 10) = t;

	/* Make ether type invalid */
	*(unsigned short *)(data + 12) = 0x3412;

	__builtin_memcpy(data + 14, data + 22, 8);

	short_data = (unsigned short *)(data + 22);
	__builtin_memmove(short_data, short_data + 1, 16);

	int_data = (unsigned int *)(data + 40);
	__builtin_memmove(int_data, int_data + 1, 32);

	return XDP_TX;
}
