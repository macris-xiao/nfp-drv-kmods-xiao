#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"
#include "bpf_shared.h"

#define THRU	TC_ACT_UNSPEC
#define DROP	TC_ACT_SHOT

struct bpf_elf_map __section("maps") map_drops = {
	.type=BPF_MAP_TYPE_ARRAY,
	.id=BPF_MAP_ID_DROPS,
	.size_key=sizeof(uint32_t),
	.size_value=sizeof(long),
	.max_elem=64,
};

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	uint32_t w = load_word(skb, 0);
	uint32_t *count;

	count = map_lookup_elem(&map_drops, &w);
	if (count)
		/* Only this cpu is accessing this element. */
		(*count)++;

	return THRU;
}
