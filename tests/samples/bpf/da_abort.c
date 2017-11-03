#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	if (load_byte(skb, 1300))
		return TC_ACT_SHOT;
	return TC_ACT_STOLEN;
}
