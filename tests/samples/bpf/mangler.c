#include <linux/bpf.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"
#include "bpf_helpers.h"

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	__u32 val, off;

	val = bpf_get_prandom_u32();
	if (val >= (~0U / 10000))
		return TC_ACT_OK;

	off = skb->len - val % 64;
	bpf_skb_load_bytes(skb, off, &val, 1);
	val ^= 1;
	bpf_skb_store_bytes(skb, off, &val, 1, BPF_F_RECOMPUTE_CSUM);

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
