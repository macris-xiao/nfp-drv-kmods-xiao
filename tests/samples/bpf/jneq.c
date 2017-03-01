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

#define TRU 0
#define DROP ~0U

#define RESa (2 * 0xaaaaaaaaULL)
#define RESb (2 * 0xbbbbbbbbULL)
#define RESc (2 * 0xccccccccULL)

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	__u64 sum = 0;

	sum += load_word(skb, 100);
	sum += load_word(skb, 104);

	if (sum != RESa)
		return DROP;

	return TRU;
}
