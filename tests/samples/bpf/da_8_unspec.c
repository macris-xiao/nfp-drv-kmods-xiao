#include <linux/filter.h>
#include <linux/bpf.h>

#include "bpf_api.h"

__section_cls_entry
int cls_entry(struct __sk_buff *skb __attribute__((unused)))
{
	return 8;
}
