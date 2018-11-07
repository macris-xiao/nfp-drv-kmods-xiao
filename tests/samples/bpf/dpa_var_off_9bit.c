#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"

#define THRU	TC_ACT_UNSPEC
#define DROP	TC_ACT_SHOT

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	unsigned char *data, *new_base;
	unsigned int var_off;

	data = (void *)(unsigned long)skb->data;
	if (data + 64 > (unsigned char *)(unsigned long)skb->data_end)
		return DROP;

	var_off = *(unsigned int *)&data[32];
	var_off &= 0x1ff;
	new_base = data + var_off;
	if (new_base + 32 > (unsigned char *)(unsigned long)skb->data_end)
		return DROP;

	if (new_base[0] != 0xaa)
		return DROP;

	return THRU;
}
