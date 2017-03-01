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
	__u32 w = 0x01020304;

	skb_store_bytes(skb, 0, &w, 4, 0);

	return TRU;
}
