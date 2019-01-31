.include "xdp.S"

xdp_prog1:
// int xdp_prog1(struct xdp_md *xdp __attribute__((unused))) {
	*(u64 *)(r10 - 16) = r1
	r1 = 0
// unsigned char foo[16] = "foo";
	*(u64 *)(r10 - 24) = r1
	r2 = 7303014
	*(u64 *)(r10 - 32) = r2
// unsigned char bar[16] = "bar";
	*(u64 *)(r10 - 40) = r1
	r1 = 7496034
	*(u64 *)(r10 - 48) = r1
	r1 = r10
// unsigned char foo[16] = "foo";
	r1 += -32
	r2 = r10
	r2 += -48
// if (one_starts_like_baz(foo, bar))
	call one_starts_like_baz
	r0 <<= 32
	r0 >>= 32
	if r0 == 0 goto LBB0_2
	goto LBB0_1

LBB0_1:
// return XDP_PASS;
	r1 = XDP_PASS
	*(u32 *)(r10 - 4) = r1
	goto LBB0_3

LBB0_2:
// return XDP_DROP;
	r1 = XDP_DROP
	*(u32 *)(r10 - 4) = r1
	goto LBB0_3

LBB0_3:
// }
	r0 = *(u32 *)(r10 - 4)
	exit

/* CHECK-CODEGEN-TIMES-2: .*rtn\[gprA_\d\].* */

one_starts_like_baz:
// static int one_starts_like_baz(unsigned char *a, unsigned char *b) {
	*(u64 *)(r10 - 8) = r1
	*(u64 *)(r10 - 16) = r2
// unsigned char baz[8] = "baz";
	r1 = 8020322
	*(u64 *)(r10 - 24) = r1
// _if (*a == b*)
	r1 = *(u64 *)(r10 - 8)
	r1 = *(u8 *)(r1 + 0)
	r2 = *(u64 *)(r10 - 16)
	r2 = *(u8 *)(r2 + 0)
	if r1 != r2 goto LBB1_2
	goto LBB1_1

LBB1_1:
// res = same_first_char(a, baz);
	r1 = *(u64 *)(r10 - 8)
	r2 = r10
	r2 += -24
	call same_first_char
	*(u32 *)(r10 - 28) = r0
	goto LBB1_7

LBB1_2:
// res = same_first_char(a, baz) || same_first_char(b, baz);
	r1 = *(u64 *)(r10 - 8)
	r2 = r10
	r2 += -24
	call same_first_char
	r0 <<= 32
	r0 >>= 32
	r1 = 1
	if r0 != 0 goto LBB1_6
	goto LBB1_3

LBB1_3:
	r1 = *(u64 *)(r10 - 16)
	r2 = r10
	r2 += -24
	call same_first_char
	r0 <<= 32
	r0 >>= 32
	r1 = 1
	if r0 != 0 goto LBB1_5
	r1 = 0

LBB1_5:
	goto LBB1_6

LBB1_6:
	r1 &= 1
	*(u32 *)(r10 - 28) = r1
	goto LBB1_7

LBB1_7:
// return res;
	r0 = *(u32 *)(r10 - 28)
	exit

same_first_char:
// static int same_first_char(unsigned char *a, unsigned char *baz) {
	*(u64 *)(r10 - 8) = r1
	*(u64 *)(r10 - 16) = r2
// return (*a == *baz);
	r1 = *(u64 *)(r10 - 8)
	r1 = *(u8 *)(r1 + 0)
	r2 = *(u64 *)(r10 - 16)
	r2 = *(u8 *)(r2 + 0)
	r0 = 1
	if r1 == r2 goto LBB2_2
	r0 = 0

LBB2_2:
	exit
