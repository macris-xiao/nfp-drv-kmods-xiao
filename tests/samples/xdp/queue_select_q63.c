#include <linux/bpf.h>

int xdp_prog1(struct xdp_md *xdp) {
	xdp->rx_queue_index = 63;

	return XDP_PASS;
}