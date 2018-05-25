
// BLOCK 3 START
	if (iph->version != 4){
		bpf_debug("IP Not version 4\n");
		return XDP_PASS;
	} else if (iph->ihl != 5){
		bpf_debug("Wrong IP Header Len\n");
		return XDP_PASS;
	} else if (iph->version == 56){
		bpf_debug("Wrong IP version\n");
		return XDP_PASS;
	} else if (ntohs(iph->tot_len) < 30){
		bpf_debug("IP Totlen too small\n");
		return XDP_PASS;
	} else if (iph->ttl == 74){
		bpf_debug("IP TTL is 74\n");
		return XDP_PASS;
	} else if (iph->check == 62049){
		bpf_debug("IP checksum is 62049\n");
		return XDP_PASS;
	} else if (iph->saddr == 12929){
		bpf_debug("Blacklisted IP Addr\n");
		return XDP_PASS;
	} else if (((iph->saddr >> 16) & 0xFFFF) == 65535){
		bpf_debug ("IP ends in 255.255\n");
		return XDP_PASS;
	}

	__u16 oldcheck = iph->check;
	iph_checksum(iph);

	if (oldcheck != iph->check){
		bpf_debug("Checksum recalc failed\n");
		return XDP_PASS;
	}

	// SWAP IPs
	__u32 temp_sip = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = temp_sip;
// BLOCK 3 END
