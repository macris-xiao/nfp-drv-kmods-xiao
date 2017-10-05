/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "../bpf/bpf_api.h"
#include "../bpf/bpf_helpers.h"

struct vlan_hdr {
	__u16 vid;
	__u16 h_vlan_encapsulated_proto;
};

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 2048,
};

static int parse_ipv4(void *data, __u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static int parse_ipv6(void *data, __u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	long *value;
	__u16 h_proto;
	__u64 nh_off;
	__u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		ipproto = parse_ipv4(data, nh_off, data_end);
		nh_off += sizeof(struct iphdr);
	} else if (h_proto == htons(ETH_P_IPV6)) {
		ipproto = parse_ipv6(data, nh_off, data_end);
		nh_off += sizeof(struct ipv6hdr);
	} else {
		return XDP_PASS;
	}

	if (ipproto != IPPROTO_TCP)
		return XDP_PASS;

	data += nh_off;
	if (data + 4 > data_end)
		return XDP_PASS;

	value = bpf_map_lookup_elem(&rxcnt, data);
	if (!value)
		return XDP_PASS;

	return *value;
}

char _license[] SEC("license") = "GPL";
