/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2016-2018 Netronome Systems, Inc. */

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
