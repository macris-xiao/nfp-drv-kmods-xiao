#include <linux/bpf.h>

#define _htons __builtin_bswap16
#define _htonl __builtin_bswap32
#define _htonq __builtin_bswap64

int xdp_prog1(struct xdp_md *xdp) {
	unsigned char *data, *data2;

	data2 =	data = (void *)(unsigned long)xdp->data;
	if (data + 80 > (unsigned char *)(unsigned long)xdp->data_end)
		return XDP_ABORTED;

	if (*(unsigned short *)(data + 12) != 0x2212)
		return XDP_DROP;

	data += 14;
	*(unsigned short *)data = _htons(*(unsigned short *)data);
	data += 2;
	*(unsigned int *)data = _htonl(*(unsigned int *)data);
	data += 4;
	*(unsigned long long *)data = _htonq(*(unsigned long long *)data);
	data += 8;
	*(unsigned long long *)data = _htons(*(unsigned short *)data);
	data += 8;
	*(unsigned long long *)data = _htonl(*(unsigned int *)data);
	data += 8;

	return XDP_PASS;
}
