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

	return TRU;
}
