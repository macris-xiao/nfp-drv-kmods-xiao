#include <linux/bpf.h>

__attribute__((noinline))
static char add4(unsigned char *c) {
	unsigned char foo[64];
	int i, res = 0;

#pragma clang loop unroll(full)
	for (i = 0; i < 64; i++)
		foo[i] = (unsigned char)(i % 8);

#pragma clang loop unroll(full)
	for (i = 0; i < 64 / 2; i += 8)
		if (foo[i] + foo[64 - 1 - i] == 7)
			res++;

	return (char)(res + *c);
}

/* CHECK-CODEGEN: .*rtn\[gprA_\d\].* */
/* CHECK-CODEGEN: .*\*l\$index3.* */
int xdp_prog1(struct xdp_md *xdp __attribute__((unused))) {
	unsigned char *data, *data_end;

	data = (void *)(unsigned long)xdp->data;
	data_end = (void *)(unsigned long)xdp->data_end;

	if (data + 1 > data_end)
		return XDP_DROP;

	/* Test always succeeds */
	if (add4(data) == *data + 4)
		return XDP_PASS;
	else
		return XDP_DROP;
}
