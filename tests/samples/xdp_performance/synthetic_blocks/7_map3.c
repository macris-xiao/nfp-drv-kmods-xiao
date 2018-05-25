
// Map Lookup 3
	key = th->seq & MASK;
	if(!map_lookup(key, &maplook_count)){
		bpf_debug("Return XDP due to lookup missing\n");
		return XDP_DROP;
	}
// Map Lookup 3
