#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/bpf.h>

/* Common, shared definitions with ebpf_agent.c. */
#include "bpf_api.h"

#define TRU 0
#define DROP ~0U

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	__u32 w;

	w = load_word(skb, 201);
	if (w == 0xaaaaaaaa)
		return DROP;

	skb->mark = 0xcafe;

	w = load_word(skb, 1000);
	if (w == 0xaaaaaaaa)
		return DROP;

	return TRU;
}
