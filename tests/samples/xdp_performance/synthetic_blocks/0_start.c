#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
	#define bpf_debug(fmt, ...)						\
	({							\
		char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			     ##__VA_ARGS__);			\
	})
#else
	#define bpf_debug(fmt, ...) { } while(0)
#endif

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = MAXENTRIES,
};

struct bpf_map_def SEC("maps") rand = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = MAXENTRIES,
};

static void iph_checksum(struct iphdr *iph){
	__u16 *next_iph_u16 = (__u16 *)iph;
	__u32 csum = 0;

	iph->check = 0; //zero existing csum
	#pragma clang loop unroll(full)
	for (int i = 0; i < (int)(sizeof(*iph) >> 1); i++){
		csum += (*next_iph_u16++);
	}
	iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static void tcp_checksum(void *data,void *data_end, __u16 datasize){
	// this function does not perform a full csum
	// it is missing the pseudo header in its calculation
	struct tcphdr *th = data;
	__u16 *data_16 = (__u16 *)data;
	__u32 csum = 0;

	if ((void*)(data_16+1) > data_end)
		return;

	th->check = 0; // set existing csum to zero

	#pragma clang loop unroll(full)
	for (int i = 0; i < datasize; i++){
		csum += *data_16++;
		if ((void*)(data_16 + 1) > data_end){
			th->check = ~((csum & 0xffff) + (csum >> 16));
			return;
		}
	}
}

static int map_lookup(int key, __u8 *maplook_count){
	__u64 *value = bpf_map_lookup_elem(&rand, &key);
	*maplook_count += 1;

	if (!value){
		bpf_debug("Rand lookup %d key %d failed\n", *maplook_count, key);
		return 0;
	}
	if (XADD)
		__sync_fetch_and_add(value, 1);
	return 1;
}

int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph;
	struct tcphdr *th;
	__u8 ip_header_length = 0;
	__u8 maplook_count = 0;
	__u16 h_proto = 0;
	__u64 nh_off;
	__u64 *value;

	/*** Ethernet Header ***/
	struct ethhdr *eth = data;
	nh_off = sizeof(*eth);

	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;
