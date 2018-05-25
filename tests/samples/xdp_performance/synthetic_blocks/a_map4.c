
// Map Lookup 4
	key = ((th->dest << 16) + th->source) & MASK;
	if(!map_lookup(key, &maplook_count)){
		bpf_debug("Return XDP due to lookup missing\n");
		return XDP_DROP;
	}
// Map Lookup 4
