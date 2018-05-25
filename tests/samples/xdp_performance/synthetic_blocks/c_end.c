
// Map Lookup 5
	// This map lookup will determine packet outcome
	maplook_count++;
	ports = ports & MASK;
	value = bpf_map_lookup_elem(&rxcnt, &ports);

	if (!value){
		bpf_debug("Cant find key %d in rxcnt map\n", ports);
		return XDP_DROP;
	}

	return *value;
// Map Lookup 5
}

char _license[] SEC("license") = "GPL";
