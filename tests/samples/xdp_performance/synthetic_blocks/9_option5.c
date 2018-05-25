
// BLOCK 5
	// Recalc Checksum
	__u16 packet_length = ntohs(iph->tot_len) + sizeof(*eth);
	__u16 tcpchecksumlength = packet_length - sizeof(*eth) - ip_header_length;

	if ((data + tcpchecksumlength) > data_end){
		bpf_debug("Packet size error\n");
		return XDP_DROP;
	}
	tcp_checksum(data, data_end, 40); // up to 40B (20B payload)
// BLOCK 5 END
