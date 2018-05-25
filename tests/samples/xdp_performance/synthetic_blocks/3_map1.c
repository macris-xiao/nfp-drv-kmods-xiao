
// Map Lookup 1
	__u32 key;
	key = (((iph->saddr & 0xFFFF) << 16) + iph->id) & MASK;
	if(!map_lookup(key, &maplook_count)){
		bpf_debug("Return XDP due to lookup missing\n");
		return XDP_DROP;
	}
// Map Lookup 1
