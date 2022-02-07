#include <linux/bpf.h>
#include "../bpf/bpf_helpers.h"

static int do_adjust_head(struct xdp_md *xdp, int delta, unsigned char *data);

int xdp_prog1(struct xdp_md *xdp)
{
	unsigned char *data_end = (void *)(unsigned long)xdp->data_end;
	unsigned char *data = (void *)(unsigned long)xdp->data;
	int new_len, old_len = data_end - data;

	if (data + 1 > data_end)
		return XDP_ABORTED;

	if (do_adjust_head(xdp, -16, data))
		return XDP_ABORTED;

	data_end = (void *)(unsigned long)xdp->data_end;
	data = (void *)(unsigned long)xdp->data;
	new_len = data_end - data;
	if (new_len != old_len + 16)
		return XDP_ABORTED;
	if (data + 1 > data_end)
		return XDP_ABORTED;

	if (do_adjust_head(xdp, 16, data))
		return XDP_ABORTED;

	data_end = (void *)(unsigned long)xdp->data_end;
	data = (void *)(unsigned long)xdp->data;
	new_len = data_end - data;
	if (new_len != old_len)
		return XDP_ABORTED;

	if (bpf_xdp_adjust_head(xdp, -16) || bpf_xdp_adjust_head(xdp, 16))
		return XDP_ABORTED;

	return XDP_PASS;
}

/* CHECK-CODEGEN: .*rtn\[gprA_\d\].* */
__attribute__ ((noinline))
static int do_adjust_head(struct xdp_md *xdp, int delta, unsigned char *data)
{
	if (!data || *data == 0xef)
		return -1;

	if (bpf_xdp_adjust_head(xdp, delta))
		return -1;

	return 0;
}
