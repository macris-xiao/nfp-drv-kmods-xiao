
// BLOCK 2 START
	unsigned char banned_mac_src[6];
	banned_mac_src[0] = 0x00;
	banned_mac_src[1] = 0x15;
	banned_mac_src[2] = 0x4d;
	banned_mac_src[3] = 0x0e;
	banned_mac_src[4] = 0x04;
	banned_mac_src[5] = 0xFE;

	if((banned_mac_src[0] == eth->h_dest[0])
		&& (banned_mac_src[1] == eth->h_dest[1])
		&& (banned_mac_src[2] == eth->h_dest[2])
		&& (banned_mac_src[3] == eth->h_dest[3])
		&& (banned_mac_src[4] == eth->h_dest[4])
		&& (banned_mac_src[5] == eth->h_dest[5]))
	{
			return XDP_PASS;
	}

	banned_mac_src[0] = 0x01;
	banned_mac_src[1] = 0x16;
	banned_mac_src[2] = 0x4F;
	banned_mac_src[3] = 0x0A;
	banned_mac_src[4] = 0x0A;
	banned_mac_src[5] = 0xFD;

	if((banned_mac_src[0] == eth->h_dest[0])
		&& (banned_mac_src[1] == eth->h_dest[1])
		&& (banned_mac_src[2] == eth->h_dest[2])
		&& (banned_mac_src[3] == eth->h_dest[3])
		&& (banned_mac_src[4] == eth->h_dest[4])
		&& (banned_mac_src[5] == eth->h_dest[5]))
	{
			return XDP_PASS;
	}

	banned_mac_src[0] = 0x0E;
	banned_mac_src[1] = 0x1B;
	banned_mac_src[2] = 0x4B;
	banned_mac_src[3] = 0x0A;
	banned_mac_src[4] = 0x04;
	banned_mac_src[5] = 0xAB;

	if((banned_mac_src[0] == eth->h_dest[0])
		&& (banned_mac_src[1] == eth->h_dest[1])
		&& (banned_mac_src[2] == eth->h_dest[2])
		&& (banned_mac_src[3] == eth->h_dest[3])
		&& (banned_mac_src[4] == eth->h_dest[4])
		&& (banned_mac_src[5] == eth->h_dest[5]))
	{
			return XDP_PASS;
	}

	//SWAP MACS
	unsigned short *p = data;
	unsigned short dst[3];
	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
// BLOCK 2 END
