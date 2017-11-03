#include <linux/filter.h>
#include <linux/bpf.h>

#include "bpf_api.h"

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	if (load_byte(skb, 1300))
		return 4;
	return 2;
}
