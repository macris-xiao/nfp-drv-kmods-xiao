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

#ifndef NFP_TEST_HARNESS_H
#define NFP_TEST_HARNESS_H 1

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct nth {
	struct mutex lock;
	struct dentry *dir;

	u8 id;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	u32 hwinfo_static_db;
#else
	bool hwinfo_static_db;
#endif
	u8 hwinfo_key_data[1024];
	struct debugfs_blob_wrapper hwinfo_key;
	u8 hwinfo_val_data[1024];
	struct debugfs_blob_wrapper hwinfo_val;

	u8 rtsym_key_data[1024];
	struct debugfs_blob_wrapper rtsym_key;

	u8 fw_load_data[1024];
	struct debugfs_blob_wrapper fw_load;

	u8 wr_only_data[1024];
	struct debugfs_blob_wrapper wr_only;

	struct debugfs_blob_wrapper fwdump;
	struct debugfs_blob_wrapper dumpspec;
	u32 dump_level;

	struct {
		const char *name;
		struct nfp_resource *res;
	} resources[1024];

	struct list_head rand;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	u32 rand_trigger_warns;
#else
	bool rand_trigger_warns;
#endif
};

extern struct nth nth;

extern const struct file_operations nth_rand_r_ops;

#endif
