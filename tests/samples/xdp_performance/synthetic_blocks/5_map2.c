
// Map Lookup 2
	key = iph->saddr & MASK;
	if(!map_lookup(key, &maplook_count)){
		bpf_debug("Return XDP due to lookup missing\n");
		return XDP_DROP;
	}
// Map Lookup 2
