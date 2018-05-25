
	/*** IP Header ***/
	if (h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	iph = data + nh_off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	__u32 ipproto = iph->protocol;
	ip_header_length = (iph->ihl) * 4;
