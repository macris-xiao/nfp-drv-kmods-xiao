#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp)
{
	unsigned char *data, *new_base;
	unsigned int var_off;

	data = (void *)(unsigned long)xdp->data;
	if (data + 64 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_DROP;

	var_off = *(unsigned int *)&data[32];
	var_off &= 0x7ff;
	new_base = data + var_off;
	if (new_base + 32 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_DROP;

	if (new_base[0] != 0x01)
		return XDP_DROP;

	return XDP_PASS;
}
