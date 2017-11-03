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
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"
#include "bpf_shared.h"

#define THRU	TC_ACT_UNSPEC
#define DROP	TC_ACT_SHOT

static int tcp_check_port(struct __sk_buff *skb, __u32 offset)
{
	__u16 tcp_port = load_half(skb, offset + 2);

	if (tcp_port == 58)
		return DROP;
	return THRU;
}

static int l3_ip(struct __sk_buff *skb, __u32 offset)
{
	__u8 l4_proto =
		load_byte(skb, offset + offsetof(struct iphdr, protocol));

	if (l4_proto == IPPROTO_TCP)
		return tcp_check_port(skb, offset + sizeof(struct iphdr));
	return THRU;
}

static int l3_ipv6(struct __sk_buff *skb, __u32 offset)
{
	__u8 l4_proto =
		load_byte(skb, offset + offsetof(struct ipv6hdr, nexthdr));

	if (l4_proto == IPPROTO_TCP)
		return tcp_check_port(skb, offset + sizeof(struct iphdr));
	return THRU;
}

static int l2_to_l3(struct __sk_buff *skb, __u16 proto, __u32 offset)
{
	if (proto == ETH_P_IP)
		return l3_ip(skb, offset);
	else if (proto == ETH_P_IPV6)
		return l3_ipv6(skb, offset);

	return THRU;
}

static int l2_vlan1(struct __sk_buff *skb, __u32 offset)
{
	__u16 proto;

	proto = load_half(skb, offset + 2);

	return l2_to_l3(skb, proto, offset + sizeof(struct ethhdr));
}

static int l2(struct __sk_buff *skb, __u32 offset)
{
	__u16 proto;

	proto = load_half(skb, offset + offsetof(struct ethhdr, h_proto));

	if (proto == ETH_P_8021Q)
		return l2_vlan1(skb, offset + sizeof(struct ethhdr));
	else
		return l2_to_l3(skb, proto, offset + sizeof(struct ethhdr));
}

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	return l2(skb, 0);
}

BPF_LICENSE("GPL");
