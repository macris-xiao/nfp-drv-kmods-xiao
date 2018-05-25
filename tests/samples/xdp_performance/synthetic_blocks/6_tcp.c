
	/*** TCP HEADER ***/
	nh_off += sizeof(struct iphdr);
	if (ipproto != IPPROTO_TCP){
		bpf_debug("not TCP\n");
		return XDP_PASS;
	}

	data += nh_off;
	th = data;
	if (data + sizeof(*th) > data_end)
		return XDP_DROP;
	__u32 ports;
	ports = *(__u32 *)data;
