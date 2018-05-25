
// BLOCK 1 START
	__u16 extend_size = 20; // length of ipv4 header
	if (bpf_xdp_adjust_head(ctx, 0 - extend_size))
		return XDP_DROP;
	void *data_ext_start = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	data = data_ext_start + extend_size;

	// Shift ethernet header to head
	struct ethhdr *new_eth = data_ext_start;
	struct ethhdr *existing_eth = data;
	if((void*)(existing_eth + 1) > data_end)
		return XDP_DROP;

	memcpy(new_eth, existing_eth, sizeof(*existing_eth));

	// Create new ip header after eth header
	iph = data + sizeof(*eth);
	struct iphdr *iph_new = data_ext_start + sizeof(*eth);

	if ((void*)(iph + 1) > data_end)
		return XDP_DROP;

	ip_header_length = (iph->ihl) * 4;
	memcpy(iph_new, iph, 20);

	iph_new->tot_len += ntohs(extend_size);
	iph_new->protocol = IPPROTO_IPIP;
	iph_checksum(iph_new);
// BLOCK 1 END
