#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"
#include "bpf_shared.h"

#define THRU	TC_ACT_UNSPEC
#define DROP	TC_ACT_SHOT

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	__u32 w = 0x01020304;

	skb_store_bytes(skb, 0, &w, 4, 0);

	return THRU;
}
