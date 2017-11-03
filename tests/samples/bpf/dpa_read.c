#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"

#define THRU	TC_ACT_UNSPEC
#define DROP	TC_ACT_SHOT

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	unsigned char *data;
	unsigned short *data2;
	unsigned int *data4;
	unsigned long long *data8;

	data = (void *)(unsigned long)skb->data;
	if (data + 64 > (unsigned char *)(unsigned long)skb->data_end)
		return DROP;

	data += 32;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data[0] != 0x01 || data[1] != 0x02 ||
	    data[2] != 0x03 || data[3] != 0x04)
		return DROP;

	if (data2[0] != 0x0201 || data2[1] != 0x0403)
		return DROP;

	if (data4[0] != 0x04030201)
		return DROP;

	if (data8[0] != 0x0807060504030201)
		return DROP;

	data += 1;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data[0] != 0x02 || data[1] != 0x03 ||
	    data[2] != 0x04 || data[3] != 0x05)
		return DROP;

	if (data2[0] != 0x0302 || data2[1] != 0x0504)
		return DROP;

	if (data4[0] != 0x05040302)
		return DROP;

	if (data8[0] != 0xbb08070605040302)
		return DROP;

	data -= 2;
	data2 = (void *)data;
	data4 = (void *)data;
	data8 = (void *)data;

	if (data[0] != 0xaa || data[1] != 0x01 ||
	    data[2] != 0x02 || data[3] != 0x03)
		return DROP;

	if (data2[0] != 0x01aa || data2[1] != 0x0302)
		return DROP;

	if (data4[0] != 0x030201aa)
		return DROP;

	if (data8[0] != 0x07060504030201aa)
		return DROP;

	return THRU;
}
