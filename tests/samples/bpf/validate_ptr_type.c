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
	__u8 *dp1;

	dp1 = (void *)(long)skb->queue_mapping;

	if (dp1 + 0x100 > (__u8 *)(long)skb->data_end)
		/* packet too small */
		return THRU;

	if (*(dp1 + 0xb4))
		return DROP;

	return THRU;
}
