#include <linux/bpf.h>

#define __noinline__ __attribute__((noinline))

static __noinline__ int func_a(unsigned char x) {
	return x + 1;
}

static __noinline__ int func_b(unsigned char x) {
	return func_a(x + 2);
}

static __noinline__ int func_c(unsigned char x) {
	return func_b(x + 3);
}

static __noinline__ int func_d(unsigned char x) {
	return func_c(x + 4);
}

static __noinline__ int func_e(unsigned char x) {
	return func_d(x + 5);
}

static __noinline__ int func_f(unsigned char x) {
	return func_e(x + 6);
}

static __noinline__ int func_g(unsigned char x) {
	return func_f(x + 7);
}

/* CHECK-CODEGEN-TIMES-7: .*rtn\[gprA_\d\].* */

int xdp_prog1(struct xdp_md *xdp __attribute__((unused))) {
	unsigned char *data, *data_end;

	data = (void *)(unsigned long)xdp->data;
	data_end = (void *)(unsigned long)xdp->data_end;

	if (data + 39 + 1 > data_end)
		return XDP_DROP;

	/* Pass iff data[14] is 0xaa */
	if (func_g(*(data + 14)) == 0xaa + 7 + 6 + 5 + 4 + 3 + 2 + 1)
		return XDP_PASS;

	return XDP_DROP;
}
