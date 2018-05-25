
// BLOCK 4 START
	if (th->seq == 0x01){
		bpf_debug("Seq number is 0x01\n");
		return XDP_PASS;
	} else if (th->ack_seq == 0x01){
		bpf_debug("Ack is 0x01\n");
		return XDP_PASS;
	} else if (th->ack_seq == 0x02){
		bpf_debug("Seq ack is 0x02\n");
		return XDP_PASS;
	} else if (th->check == 0){
		bpf_debug("Incorrect checksum\n");
		return XDP_PASS;
	} else if (th->urg_ptr > 0x01){
		bpf_debug("Incorrect urgent flag tcp\n");
		return XDP_TX;
	} else if (th->syn && th->fin){
		bpf_debug("Both Syn and Fin set\n");
		return XDP_PASS;
	} else if (htons(th->dest) == 22 && htons(th->source) == 5){
		bpf_debug("Accessing ssh port from port 5\n");
		return XDP_PASS;
	} else if (htons(th->dest) == 80 && htons(th->source) == 32){
		bpf_debug("Accessing HTTP port from port 32\n");
		return XDP_PASS;
	} else if (htons(th->dest) == 443 && htons(th->source) == 91){
		bpf_debug("Accessing HTTPS port from port 91\n");
		return XDP_PASS;
	}
	__u16 tempport = th->source;
	th->source = th->dest;
	th->dest = tempport;
// BLOCK 4 END
