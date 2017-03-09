/*
 * Copyright (C) 2016-2017 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "nfpcore/kcompat.h"

#include <linux/debugfs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/random.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp.h"
#include "nfpcore/nfp6000/nfp6000.h"
#include "nfp_test_harness.h"

/* Set to 1 to test oversize reads/area handling */
#define NTH_GENERATE_OVERSIZED_ACCESSES		0

struct nth_rand_entry {
	struct list_head list;
	pid_t pid;
	char type;
	u32 addr;
	u32 size;

	u32 rand;
	u64 cntr;
	u64 delta;
};

static int nth_rand_r_read(struct seq_file *file, void *data)
{
	struct nth_rand_entry *rand;

	mutex_lock(&nth.lock);
	list_for_each_entry(rand, &nth.rand, list) {
		rand->cntr += rand->delta;
		seq_printf(file, "%d [%08x]  %c %08x %04x  %llu \t %llu\n",
			   rand->pid, rand->rand,
			   rand->type, rand->addr, rand->size,
			   rand->cntr, rand->delta);
		rand->delta = 0;
	}
	mutex_unlock(&nth.lock);

	return 0;
}

static void
nth_update_rand_state(struct nth_rand_entry *entry, char type,
		      u32 addr, u32 size)
{
	entry->type = type;
	entry->addr = addr;
	entry->size = size;
}

static u32 nth_rand_size(u32 max)
{
	u32 ret;

	while (!(ret = prandom_u32_max(max) & ~0x7))
		;
	return ret;
}

static u32 nth_rand_addr(u32 size)
{
	u32 addr;

	addr = prandom_u32() & ~(3 << 31 | 0x7);
	if (!READ_ONCE(nth.rand_trigger_warns))
		if (round_down(addr, 0x100000) !=
		    round_down(addr + size, 0x100000))
			addr -= size;

	return addr;
}

static void
nth_rand_read_res(struct nfp_cpp *cpp, struct nth_rand_entry *entry,
		  u8 *buff, const u8 *expect, u32 max_size)
{
	struct nfp_resource *res;
	int size, addr, val;

	nth_update_rand_state(entry, 't', 0, 0);
	res = nfp_resource_acquire(cpp, NFP_RESOURCE_NFP_NFFW);
	if (IS_ERR(res)) {
		pr_err("ERR: Resource acqurie failed %ld!\n",
		       PTR_ERR(res));
		return;
	}

	addr = nfp_resource_address(res);
	size = min_t(u64, max_size, nfp_resource_size(res));
	nth_update_rand_state(entry, 'T', addr, size);
	val = nfp_cpp_read(cpp, nfp_resource_cpp_id(res),
			   addr, buff, size);
	if (val != size)
		pr_err("ERR: resource read failed %d vs %d\n", val, size);
	nfp_resource_release(res);

	if (expect && memcmp(buff, expect, size))
		pr_err("ERR: resource read incorrect\n");
}

static ssize_t nth_rand_r_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct nth_rand_entry entry = {};
	struct nfp_eth_table *eth_table;
	struct nfp_cpp *cpp;
	u8 *buffer;
	u8 *nffw;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	eth_table = nfp_eth_read_ports(cpp);
	if (!eth_table) {
		nfp_cpp_free(cpp);
		return -EIO;
	}

#define NTH_RAND_R_BUFSZ	(1 << 14)
	buffer = kmalloc(NTH_RAND_R_BUFSZ, GFP_KERNEL);
	nffw = kmalloc(NTH_RAND_R_BUFSZ, GFP_KERNEL);
	if (!buffer || !nffw)
		goto out;

	entry.pid = task_pid_nr(current);

	mutex_lock(&nth.lock);
	list_add_tail(&entry.list, &nth.rand);
	mutex_unlock(&nth.lock);

	nth_rand_read_res(cpp, &entry, nffw, NULL, NTH_RAND_R_BUFSZ);

	while (!signal_pending(current)) {
		u32 dst = NFP_CPP_ID(NFP_CPP_TARGET_MU, NFP_CPP_ACTION_RW, 0) |
			NFP_ISL_EMEM0;
		u32 dice;

		dice = prandom_u32();
		entry.rand = dice;
		entry.delta++;

		/* NSP is slow, make it less common */
		if (!(dice & 0xfff)) {
			void *res;

			nth_update_rand_state(&entry, 'e', 0, 0);
			res = nfp_eth_read_ports(cpp);
			if (!res) {
				pr_err("ERR: Failed to read table\n");
				continue;
			}
			if (memcmp(eth_table, res, sizeof(*eth_table)))
				pr_err("ERR: ETH table doesn't match!\n");
			kfree(res);
		}
		dice >>= 12;

		if (!(dice & 0x1ff))
			nth_rand_read_res(cpp, &entry, buffer, nffw,
					  NTH_RAND_R_BUFSZ);
		dice >>= 9;

		if (dice & 1) {
			struct nfp_cpp_area *res;
			int size, addr, val;

			size = nth_rand_size(NTH_RAND_R_BUFSZ);
			addr = nth_rand_addr(size);
			nth_update_rand_state(&entry, 'a', addr, size);

			res = nfp_cpp_area_alloc_acquire(cpp, dst, addr, size);
			if (!res) {
				pr_err("ERR: Alloc/acquire area failed!\n");
				continue;
			}

			nth_update_rand_state(&entry, 'A', addr, size);
			val = nfp_cpp_area_read(res, 0, buffer, size);
			if (val != size)
				pr_err("ERR: area read failed %d vs %d\n",
				       val, size);
			nfp_cpp_area_release_free(res);
		}
		dice >>= 1;

		if (dice & 1) {
			int size, addr, val;

			size = nth_rand_size(NTH_RAND_R_BUFSZ);
			addr = nth_rand_addr(size);

			nth_update_rand_state(&entry, 'r', addr, size);
			val = nfp_cpp_read(cpp, dst, addr, buffer, size);
			if (val != size)
				pr_err("ERR: quick read failed %d vs %u\n",
				       val, size);
		}
		dice >>= 1;
	}

	mutex_lock(&nth.lock);
	list_del(&entry.list);
	mutex_unlock(&nth.lock);

	kfree(buffer);
	kfree(nffw);
out:
	kfree(eth_table);
	nfp_cpp_free(cpp);
	return 0;
}

static int nth_rand_r_open(struct inode *inode, struct file *f)
{
	return single_open(f, nth_rand_r_read, inode->i_private);
}

const struct file_operations nth_rand_r_ops = {
	.owner = THIS_MODULE,
	.open = nth_rand_r_open,
	.release = single_release,
	.read = seq_read,
	.write = nth_rand_r_write,
	.llseek = seq_lseek,
};
