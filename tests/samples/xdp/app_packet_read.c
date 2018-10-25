#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "../bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") ethmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct ethhdr),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") ip = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct iphdr),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tcp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tcphdr),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") pa = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

struct error {
	__u32 id;
	__u32 val1;
	__u32 val2;
};

static __always_inline
void debug_err(struct xdp_md *ctx, __u32 id, __u32 val1, __u32 val2)
{
	struct error err;

	err.id = id;
	err.val1 = val1;
	err.val2 = val2;

	bpf_perf_event_output(ctx, &pa, 0x1ffffffffULL, &err, sizeof(err));
}

static __always_inline
__u8 mac_check(struct xdp_md *ctx, __u32 id, char *p1, char *p2, __u16 len)
{
	int j = 0;
	#pragma clang loop unroll(full)
	for (j = 0; j < len; j++) {
		if (*p1 != *p2) {
			debug_err(ctx, id, *p1, *p2);
			return 0;
		}
		p1++;
		p2++;
	}
	return 1;
}

int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct ethhdr *eth_mapval;
	struct tcphdr *tcp_mapval;
	struct iphdr *ip_mapval;
	struct iphdr *iph;
	struct tcphdr *th;

	__u8 ret_mapfail = XDP_ABORTED;
	__u8 ret_fail = XDP_DROP;
	__u8 ret_pass = XDP_TX;
	__u32 ret = ret_pass;
	__u32 check_id = 0;
	__u32 index = 0;
	__u64 nh_off;
	char *map_mac;
	char *pkt_mac;

	/* Ignore pings and non TCP packets */
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_PASS;

	iph = data + nh_off;
	if (iph + 1 > data_end)
		return XDP_PASS;

	nh_off += sizeof(struct iphdr);
	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	th = data + nh_off;
	if (data + nh_off + sizeof(*th) > data_end)
		return XDP_PASS;

	/* Match section */
	eth_mapval = bpf_map_lookup_elem(&ethmap, &index);
	if (!eth_mapval)
		return ret_mapfail;

	ip_mapval = bpf_map_lookup_elem(&ip, &index);
	if (!ip_mapval)
		return ret_mapfail;

	tcp_mapval = bpf_map_lookup_elem(&tcp, &index);
	if (!tcp_mapval)
		return ret_mapfail;

	check_id = 1;
	map_mac = (char *)eth_mapval->h_dest;
	pkt_mac = (char *)eth->h_dest;
	if (mac_check(ctx, check_id, map_mac, pkt_mac, 6) != 1)
		ret = ret_fail;

	check_id = 2;
	map_mac = (char *)eth_mapval->h_source;
	pkt_mac = (char *)eth->h_source;
	if (mac_check(ctx, check_id, map_mac, pkt_mac, 6) != 1)
		ret = ret_fail;

	if (eth_mapval->h_proto != eth->h_proto) {
		check_id = 3;
		debug_err(ctx, check_id, eth_mapval->h_proto, eth->h_proto);
		ret = ret_fail;
	}

	if (ip_mapval->tos != iph->tos) {
		check_id = 4;
		debug_err(ctx, check_id, ip_mapval->tos, iph->tos);
		ret = ret_fail;
	}
	if (ip_mapval->tot_len != 0x00) { /* if specified in map */
		if (ip_mapval->tot_len != iph->tot_len) {
			check_id = 5;
			debug_err(ctx, check_id, ip_mapval->tot_len,
				  iph->tot_len);
			ret = ret_fail;
		}
	}
	if (ip_mapval->id != 0x00) { /* if specified in map */
		if (ip_mapval->id != iph->id) {
			check_id = 6;
			debug_err(ctx, check_id, ip_mapval->id, iph->id);
			ret = ret_fail;
		}
	}
	if (ip_mapval->frag_off != iph->frag_off) {
		check_id = 7;
		debug_err(ctx, check_id, ip_mapval->frag_off, iph->frag_off);
		ret = ret_fail;
	}
	if (ip_mapval->ttl != iph->ttl) {
		check_id = 8;
		debug_err(ctx, check_id, ip_mapval->ttl, iph->ttl);
		ret = ret_fail;
	}
	if (ip_mapval->protocol != iph->protocol) {
		check_id = 9;
		debug_err(ctx, check_id, ip_mapval->protocol, iph->protocol);
		ret = ret_fail;
	}
	if (ip_mapval->check != 0x00) { /* if specified in map */
		if (ip_mapval->check != iph->check) {
			check_id = 10;
			debug_err(ctx, check_id, ip_mapval->check, iph->check);
			ret = ret_fail;
		}
	}
	if (ip_mapval->saddr != iph->saddr) {
		check_id = 11;
		debug_err(ctx, check_id, ip_mapval->saddr, iph->saddr);
		ret = ret_fail;
	}
	if (ip_mapval->daddr != iph->daddr) {
		check_id = 12;
		debug_err(ctx, check_id, ip_mapval->daddr, iph->daddr);
		ret = ret_fail;
	}

	if (tcp_mapval->source != th->source) {
		check_id = 13;
		debug_err(ctx, check_id, tcp_mapval->source, th->source);
		ret = ret_fail;
	}
	if (tcp_mapval->dest != th->dest) {
		check_id = 14;
		debug_err(ctx, check_id, tcp_mapval->dest, th->dest);
		ret = ret_fail;
	}
	if (tcp_mapval->seq != th->seq) {
		check_id = 15;
		debug_err(ctx, check_id, tcp_mapval->seq, th->seq);
		ret = ret_fail;
	}
	if (tcp_mapval->ack_seq != th->ack_seq) {
		check_id = 16;
		debug_err(ctx, check_id, tcp_mapval->ack_seq, th->ack_seq);
		ret = ret_fail;
	}
	if (tcp_mapval->res1 != th->res1) {
		check_id = 17;
		debug_err(ctx, check_id, tcp_mapval->res1, th->res1);
		ret = ret_fail;
	}
	if (tcp_mapval->doff != th->doff) {
		check_id = 18;
		debug_err(ctx, check_id, tcp_mapval->doff, th->doff);
		ret = ret_fail;
	}
	if (tcp_mapval->fin != th->fin) {
		check_id = 19;
		debug_err(ctx, check_id, tcp_mapval->fin, th->fin);
		ret = ret_fail;
	}
	if (tcp_mapval->syn != th->syn) {
		check_id = 20;
		debug_err(ctx, check_id, tcp_mapval->syn, th->syn);
		ret = ret_fail;
	}
	if (tcp_mapval->rst != th->rst) {
		check_id = 21;
		debug_err(ctx, check_id, tcp_mapval->rst, th->rst);
		ret = ret_fail;
	}
	if (tcp_mapval->psh != th->psh) {
		check_id = 22;
		debug_err(ctx, check_id, tcp_mapval->psh, th->psh);
		ret = ret_fail;
	}
	if (tcp_mapval->ack != th->ack) {
		check_id = 23;
		debug_err(ctx, check_id, tcp_mapval->ack, th->ack);
		ret = ret_fail;
	}
	if (tcp_mapval->urg != th->urg) {
		check_id = 24;
		debug_err(ctx, check_id, tcp_mapval->urg, th->urg);
		ret = ret_fail;
	}
	if (tcp_mapval->ece != th->ece) {
		check_id = 25;
		debug_err(ctx, check_id, tcp_mapval->ece, th->ece);
		ret = ret_fail;
	}
	if (tcp_mapval->cwr != th->cwr) {
		check_id = 26;
		debug_err(ctx, check_id, tcp_mapval->cwr, th->cwr);
		ret = ret_fail;
	}
	if (tcp_mapval->window != th->window) {
		check_id = 27;
		debug_err(ctx, check_id, tcp_mapval->window, th->window);
		ret = ret_fail;
	}
	if (tcp_mapval->check != 0x00) { /* if specified in map */
		if (tcp_mapval->check != th->check) {
			check_id = 28;
			debug_err(ctx, check_id, tcp_mapval->check, th->check);
			ret = ret_fail;
		}
	}
	if (tcp_mapval->urg_ptr != th->urg_ptr) {
		check_id = 29;
		debug_err(ctx, check_id, tcp_mapval->urg_ptr, th->urg_ptr);
		ret = ret_fail;
	}

	/* MORE THAN */
	/* Subsequent map lookup to ensure compiler doesn't combine sections */
	ip_mapval = bpf_map_lookup_elem(&ip, &index);
	if (!ip_mapval)
		return ret_mapfail;

	tcp_mapval = bpf_map_lookup_elem(&tcp, &index);
	if (!tcp_mapval)
		return ret_mapfail;

	if (ip_mapval->tos > iph->tos) {
		check_id = 30;
		debug_err(ctx, check_id, ip_mapval->tos, iph->tos);
		ret = ret_fail;
	}
	if (ip_mapval->tot_len != 0x00) { /* if specified in map */
		if (ip_mapval->tot_len > iph->tot_len) {
			check_id = 31;
			debug_err(ctx, check_id, ip_mapval->tot_len,
				  iph->tot_len);
			ret = ret_fail;
		}
	}
	if (ip_mapval->id != 0x00) { /* if specified in map */
		if (ip_mapval->id > iph->id) {
			check_id = 32;
			debug_err(ctx, check_id, ip_mapval->id, iph->id);
			ret = ret_fail;
		}
	}
	if (ip_mapval->frag_off > iph->frag_off) {
		check_id = 33;
		debug_err(ctx, check_id, ip_mapval->frag_off, iph->frag_off);
		ret = ret_fail;
	}
	if (ip_mapval->ttl > iph->ttl) {
		check_id = 34;
		debug_err(ctx, check_id, ip_mapval->ttl, iph->ttl);
		ret = ret_fail;
	}
	if (ip_mapval->protocol > iph->protocol) {
		check_id = 35;
		debug_err(ctx, check_id, ip_mapval->protocol, iph->protocol);
		ret = ret_fail;
	}
	if (ip_mapval->check != 0x00) { /* if specified in map */
		if (ip_mapval->check > iph->check) {
			check_id = 36;
			debug_err(ctx, check_id, ip_mapval->check, iph->check);
			ret = ret_fail;
		}
	}
	if (ip_mapval->saddr > iph->saddr) {
		check_id = 37;
		debug_err(ctx, check_id, ip_mapval->saddr, iph->saddr);
		ret = ret_fail;
	}
	if (ip_mapval->daddr > iph->daddr) {
		check_id = 38;
		debug_err(ctx, check_id, ip_mapval->daddr, iph->daddr);
		ret = ret_fail;
	}
	if (tcp_mapval->source > th->source) {
		check_id = 39;
		debug_err(ctx, check_id, tcp_mapval->source, th->source);
		ret = ret_fail;
	}
	if (tcp_mapval->dest > th->dest) {
		check_id = 40;
		debug_err(ctx, check_id, tcp_mapval->dest, th->dest);
		ret = ret_fail;
	}
	if (tcp_mapval->seq > th->seq) {
		check_id = 41;
		debug_err(ctx, check_id, tcp_mapval->seq, th->seq);
		ret = ret_fail;
	}
	if (tcp_mapval->ack_seq > th->ack_seq) {
		check_id = 42;
		debug_err(ctx, check_id, tcp_mapval->ack_seq, th->ack_seq);
		ret = ret_fail;
	}
	if (tcp_mapval->window > th->window) {
		check_id = 43;
		debug_err(ctx, check_id, tcp_mapval->window, th->window);
		ret = ret_fail;
	}
	if (tcp_mapval->check != 0x00) { /* if specified in map */
		if (tcp_mapval->check > th->check) {
			check_id = 44;
			debug_err(ctx, check_id, tcp_mapval->check, th->check);
			ret = ret_fail;
		}
	}
	if (tcp_mapval->urg_ptr > th->urg_ptr) {
		check_id = 45;
		debug_err(ctx, check_id, tcp_mapval->urg_ptr, th->urg_ptr);
		ret = ret_fail;
	}

	/* LESS THAN */
	/* Subsequent map lookup to ensure compiler doesn't combine sections */
	ip_mapval = bpf_map_lookup_elem(&ip, &index);
	if (!ip_mapval)
		return ret_mapfail;

	tcp_mapval = bpf_map_lookup_elem(&tcp, &index);
	if (!tcp_mapval)
		return ret_mapfail;

	if (ip_mapval->tos < iph->tos) {
		check_id = 46;
		debug_err(ctx, check_id, ip_mapval->tos, iph->tos);
		ret = ret_fail;
	}
	if (ip_mapval->tot_len != 0x00) { /* if specified in map */
		if (ip_mapval->tot_len < iph->tot_len) {
			check_id = 47;
			debug_err(ctx, check_id, ip_mapval->tot_len,
				  iph->tot_len);
			ret = ret_fail;
		}
	}
	if (ip_mapval->id != 0x00) { /* if specified in map */
		if (ip_mapval->id < iph->id) {
			check_id = 48;
			debug_err(ctx, check_id, ip_mapval->id, iph->id);
			ret = ret_fail;
		}
	}
	if (ip_mapval->frag_off < iph->frag_off) {
		check_id = 49;
		debug_err(ctx, check_id, ip_mapval->frag_off, iph->frag_off);
		ret = ret_fail;
	}
	if (ip_mapval->ttl < iph->ttl) {
		check_id = 50;
		debug_err(ctx, check_id, ip_mapval->ttl, iph->ttl);
		ret = ret_fail;
	}
	if (ip_mapval->protocol < iph->protocol) {
		check_id = 51;
		debug_err(ctx, check_id, ip_mapval->protocol, iph->protocol);
		ret = ret_fail;
	}
	if (ip_mapval->check != 0x00) { /* if specified in map */
		if (ip_mapval->check < iph->check) {
			check_id = 52;
			debug_err(ctx, check_id, ip_mapval->check, iph->check);
			ret = ret_fail;
		}
	}
	if (ip_mapval->saddr < iph->saddr) {
		check_id = 53;
		debug_err(ctx, check_id, ip_mapval->saddr, iph->saddr);
		ret = ret_fail;
	}
	if (ip_mapval->daddr < iph->daddr) {
		check_id = 54;
		debug_err(ctx, check_id, ip_mapval->daddr, iph->daddr);
		ret = ret_fail;
	}
	if (tcp_mapval->source < th->source) {
		check_id = 55;
		debug_err(ctx, check_id, tcp_mapval->source, th->source);
		ret = ret_fail;
	}
	if (tcp_mapval->dest < th->dest) {
		check_id = 56;
		debug_err(ctx, check_id, tcp_mapval->dest, th->dest);
		ret = ret_fail;
	}
	if (tcp_mapval->seq < th->seq) {
		check_id = 57;
		debug_err(ctx, check_id, tcp_mapval->seq, th->seq);
		ret = ret_fail;
	}
	if (tcp_mapval->ack_seq < th->ack_seq) {
		check_id = 58;
		debug_err(ctx, check_id, tcp_mapval->ack_seq, th->ack_seq);
		ret = ret_fail;
	}
	if (tcp_mapval->window < th->window) {
		check_id = 59;
		debug_err(ctx, check_id, tcp_mapval->window, th->window);
		ret = ret_fail;
	}
	if (tcp_mapval->check != 0x00) { /* if specified in map */
		if (tcp_mapval->check < th->check) {
			check_id = 60;
			debug_err(ctx, check_id, tcp_mapval->check, th->check);
			ret = ret_fail;
		}
	}
	if (tcp_mapval->urg_ptr < th->urg_ptr) {
		check_id = 61;
		debug_err(ctx, check_id, tcp_mapval->urg_ptr, th->urg_ptr);
		ret = ret_fail;
	}

	return ret;
}

char _license[] SEC("license") = "GPL";
