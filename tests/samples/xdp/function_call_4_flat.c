#include <linux/bpf.h>

__attribute__((noinline))
static int greater_or_equal(unsigned char *a, unsigned char *b) {
	return (a >= b);
}

__attribute__((noinline))
static int lower_than(unsigned char *a, unsigned char *b) {
	return (a < b);
}

__attribute__((noinline))
static int sub_and_add(unsigned char *a, unsigned char *b, unsigned char *c) {
	return (b - a + (const unsigned char)*c);
}

/* CHECK-CODEGEN-TIMES-3: .*rtn\[gprA_\d\].* */

int xdp_prog1(struct xdp_md *xdp __attribute__((unused))) {
	unsigned char *data, *data_end;
	unsigned char foo[32], i;

	data = (void *)(unsigned long)xdp->data;
	data_end = (void *)(unsigned long)xdp->data_end;

	if (data + 1 > data_end)
		return XDP_DROP;

	/* Test always fails */
	if (lower_than(data_end, data))
		return XDP_DROP;

	/* Test always fails */
	if (greater_or_equal(data, data_end))
		data = data_end;
#pragma clang loop unroll(full)
	for (i = 0; i < 32; i++)
		foo[i] = i;
	/* Test always succeeds (returns data length + 0) */
	if (sub_and_add(data, data_end, foo))
		return XDP_PASS;

	/* Test always succeeds */
	if (greater_or_equal(data_end, data))
		return XDP_PASS;
	else
		return XDP_DROP;
}
