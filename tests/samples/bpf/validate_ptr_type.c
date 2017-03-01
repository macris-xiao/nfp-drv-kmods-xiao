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

#include "bpf_api.h"
#include "bpf_shared.h"

#define TRU 0
#define DROP ~0U

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	__u8 *dp1;

	dp1 = (void *)(long)skb->data;

	if (dp1 + 0x100 > (__u8 *)(long)skb->data_end)
		/* packet too small */
		return TRU;

	if (*(dp1 + 0xb4))
		return DROP;

	return TRU;
}
