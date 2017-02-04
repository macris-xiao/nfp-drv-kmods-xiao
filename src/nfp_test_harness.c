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
#include <linux/debugfs.h>
#include <linux/firmware.h>
#include <linux/module.h>

#include "nfpcore/kcompat.h"
#include "nfpcore/nfp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp_eth.h"

struct {
	struct dentry *dir;

	u8 id;

	u8 hwinfo_key_data[1024];
	struct debugfs_blob_wrapper hwinfo_key;
	u8 hwinfo_val_data[1024];
	struct debugfs_blob_wrapper hwinfo_val;

	u8 rtsym_key_data[1024];
	struct debugfs_blob_wrapper rtsym_key;
	u8 rtsym_val_data[1024];
	struct debugfs_blob_wrapper rtsym_val;

	u8 fw_load_data[1024];
	struct debugfs_blob_wrapper fw_load;

	u8 wr_only_data[1024];
	struct debugfs_blob_wrapper wr_only;

	struct {
		const char *name;
		struct nfp_resource *res;
	} resources[1024];
} nth = {
	.hwinfo_key = {
		.data = nth.hwinfo_key_data,
		.size = sizeof(nth.hwinfo_key_data),
	},
	.hwinfo_val = {
		.data = nth.hwinfo_val_data,
		.size = sizeof(nth.hwinfo_val_data),
	},

	.rtsym_key = {
		.data = nth.rtsym_key_data,
		.size = sizeof(nth.rtsym_key_data),
	},
	.rtsym_val = {
		.data = nth.rtsym_val_data,
		.size = sizeof(nth.rtsym_val_data),
	},

	.fw_load = {
		.data = nth.fw_load_data,
		.size = sizeof(nth.fw_load_data),
	},

	/* For all things which don't need to read things back */
	.wr_only = {
		.data = nth.wr_only_data,
		.size = sizeof(nth.wr_only_data),
	},
};

#define NTH_DECLARE_HANDLER(__name)					\
	static int							\
	nth_ ## __name ## _open(struct inode *inode, struct file *f)	\
	{								\
		return single_open(f, nth_ ## __name ## _read,		\
				   inode->i_private);			\
	}								\
									\
	static const struct file_operations nth_ ## __name ## _ops = {	\
		.owner = THIS_MODULE,					\
		.open = nth_ ## __name ## _open,			\
		.release = single_release,				\
		.read = seq_read,					\
		.llseek = seq_lseek,					\
	}

#define NTH_DECLARE_ACTION(__name, __op)				\
	static int nth_ ## __name ## _read(struct seq_file *file, void *data) \
	{								\
		struct nfp_cpp *cpp;					\
									\
		cpp = nfp_cpp_from_device_id(nth.id);			\
		if (!cpp)						\
			return -EBUSY;					\
									\
		__op(cpp);						\
									\
		nfp_cpp_free(cpp);					\
									\
		return 0;						\
	}								\
	NTH_DECLARE_HANDLER(__name);

#define NTH_DECLARE_ACTION_NSP(__name, __op)				\
	static int nth_ ## __name ## _read(struct seq_file *file, void *data) \
	{								\
		struct nfp_cpp *cpp;					\
		struct nfp_nsp *nsp;					\
		int ret;						\
									\
		cpp = nfp_cpp_from_device_id(nth.id);			\
		if (!cpp)						\
			return -EBUSY;					\
									\
		nsp = nfp_nsp_open(cpp);				\
		if (IS_ERR(nsp)) {					\
			ret = PTR_ERR(nsp);				\
			goto err_free_cpp;				\
		}							\
									\
		ret = __op(nsp);					\
									\
		nfp_nsp_close(nsp);					\
	err_free_cpp:							\
		nfp_cpp_free(cpp);					\
									\
		return ret;						\
	}								\
	NTH_DECLARE_HANDLER(__name);

static int nth_serial_read(struct seq_file *file, void *data)
{
	struct nfp_cpp *cpp;
	int size, err = 0;
	const u8 *serial;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	size = nfp_cpp_serial(cpp, &serial);
	if (size != 6) {
		err = -EINVAL;
		goto err_free;
	}

	seq_printf(file, "%pM", serial);
err_free:
	nfp_cpp_free(cpp);

	return err;
}
NTH_DECLARE_HANDLER(serial);

static int nth_interface_read(struct seq_file *file, void *data)
{
	struct nfp_cpp *cpp;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	seq_printf(file, "%04hx\n", nfp_cpp_interface(cpp));

	nfp_cpp_free(cpp);

	return 0;
}
NTH_DECLARE_HANDLER(interface);

NTH_DECLARE_ACTION(cache_flush, nfp_nffw_cache_flush);
NTH_DECLARE_ACTION_NSP(reset, nfp_nsp_device_soft_reset);

static int nth_rtsym_count_read(struct seq_file *file, void *data)
{
	struct nfp_cpp *cpp;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	seq_printf(file, "%d\n", nfp_rtsym_count(cpp));

	nfp_cpp_free(cpp);

	return 0;
}
NTH_DECLARE_HANDLER(rtsym_count);

static int nth_rtsym_dump_read(struct seq_file *file, void *data)
{
	const struct nfp_rtsym *rtsym;
	struct nfp_cpp *cpp;
	int i;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	i = 0;
	while ((rtsym = nfp_rtsym_get(cpp, i++)))
	       seq_printf(file, "%s\n", rtsym->name);

	nfp_cpp_free(cpp);

	return 0;
}
NTH_DECLARE_HANDLER(rtsym_dump);

static ssize_t nth_read_blob(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	int srcu_idx;
	ssize_t ret;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_read_from_buffer(user_buf, count, ppos,
					      blob->data, blob->size);
	debugfs_use_file_finish(srcu_idx);

	return ret;
}

static ssize_t nth_write_hwinfo(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	const char *value;
	int srcu_idx;
	ssize_t ret;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	debugfs_use_file_finish(srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	memset(nth.hwinfo_val_data, 0, sizeof(nth.hwinfo_val_data));

	value = nfp_hwinfo_lookup(cpp, data);
	if (!value) {
		ret = -EINVAL;
		goto err_free_cpp;
	}

	memcpy(nth.hwinfo_val_data, value,
	       strnlen(value, sizeof(nth.hwinfo_val_data)));

err_free_cpp:
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_hwinfo_ops = {
	.read = nth_read_blob,
	.write = nth_write_hwinfo,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t nth_write_rtsym(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	const struct nfp_rtsym *value;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	int srcu_idx;
	ssize_t ret;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	debugfs_use_file_finish(srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	memset(nth.rtsym_val_data, 0, sizeof(nth.rtsym_val_data));

	value = nfp_rtsym_lookup(cpp, data);
	if (!value) {
		ret = -EINVAL;
		goto err_free_cpp;
	}

	memcpy(nth.rtsym_val_data, value->name,
	       strnlen(value->name, sizeof(nth.rtsym_val_data)));

err_free_cpp:
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_rtsym_ops = {
	.read = nth_read_blob,
	.write = nth_write_rtsym,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t nth_write_fw_load(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	const struct firmware *fw;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	struct nfp_nsp *nsp;
	ssize_t copied, ret;
	int srcu_idx;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	debugfs_use_file_finish(srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;
	copied = ret;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	ret = request_firmware(&fw, data, nfp_cpp_device(cpp)->parent);
	if (ret < 0)
		goto err_free_cpp;

	nsp = nfp_nsp_open(cpp);
	if (IS_ERR(nsp)) {
		ret = PTR_ERR(nsp);
		goto err_release_fw;
	}

	ret = nfp_nsp_wait(nsp);
	if (ret < 0)
		goto err_nsp_close;

	ret = nfp_nsp_device_soft_reset(nsp);
	if (ret < 0) {
		pr_err("Failed to soft reset the NFP: %ld\n", ret);
		goto err_nsp_close;
	}

	ret = nfp_nsp_load_fw(nsp, fw);
	if (ret) {
		pr_err("FW loading failed: %ld\n", ret);
		goto err_nsp_close;
	}

err_nsp_close:
	nfp_nsp_close(nsp);
err_release_fw:
	release_firmware(fw);
err_free_cpp:
	nfp_cpp_free(cpp);

	return ret ? ret : copied;
}

static const struct file_operations nth_fw_load_ops = {
	.read = nth_read_blob,
	.write = nth_write_fw_load,
	.open = simple_open,
	.llseek = default_llseek,
};

static int nth_resource_read(struct seq_file *file, void *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(nth.resources); i++) {
		if (!nth.resources[i].name)
			continue;

		seq_printf(file, "%d\t%s\t%p %s\t%08x %010llx %llx\n",
			   i, nth.resources[i].name, nth.resources[i].res,
			   nfp_resource_name(nth.resources[i].res),
			   nfp_resource_cpp_id(nth.resources[i].res),
			   nfp_resource_address(nth.resources[i].res),
			   nfp_resource_size(nth.resources[i].res));
	}

	return 0;
}

static ssize_t
nth_resource_write(struct file *file, const char __user *user_buf,
		   size_t count, loff_t *ppos)
{
	struct nfp_cpp *cpp;
	ssize_t copied, ret;
	char name[16] = {};
	int srcu_idx;
	long i;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(name, sizeof(name) - 1,
					     ppos, user_buf, count);
	debugfs_use_file_finish(srcu_idx);
	if (ret < 0)
		return ret;
	copied = ret;
	ret = 0;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	if (kstrtol(name, 0, &i)) {
		for (i = 0; i < ARRAY_SIZE(nth.resources); i++)
			if (!nth.resources[i].name)
				break;
		if (i == ARRAY_SIZE(nth.resources)) {
			ret = -ENOSPC;
			goto exit_free_cpp;
		}

		nth.resources[i].name = kstrdup(name, GFP_KERNEL);
		if (!nth.resources[i].name) {
			ret = -ENOMEM;
			goto exit_free_cpp;
		}

		nth.resources[i].res = nfp_resource_acquire(cpp, name);
		if (IS_ERR(nth.resources[i].res)) {
			kfree(nth.resources[i].name);
			ret = PTR_ERR(nth.resources[i].res);
			memset(&nth.resources[i], 0, sizeof(nth.resources[i]));
		}
	} else if (nth.resources[i].name) {
		kfree(nth.resources[i].name);
		nfp_resource_release(nth.resources[i].res);
		memset(&nth.resources[i], 0, sizeof(nth.resources[i]));
	} else {
		ret = -EINVAL;
	}

exit_free_cpp:
	nfp_cpp_free(cpp);

	return ret ? ret : copied;
}

static int nth_resource_open(struct inode *inode, struct file *f)
{
	return single_open(f, nth_resource_read, inode->i_private);
}

static const struct file_operations nth_resource_ops = {
	.owner = THIS_MODULE,
	.open = nth_resource_open,
	.release = single_release,
	.write = nth_resource_write,
	.read = seq_read,
	.llseek = seq_lseek,
};

static int nth_eth_table_read(struct seq_file *file, void *data)
{
	struct nfp_eth_table *eth_table;
	struct nfp_cpp *cpp;
	int i;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	eth_table = nfp_eth_read_ports(cpp);
	if (!eth_table) {
		nfp_cpp_free(cpp);
		return -EIO;
	}

	for (i = 0; i < eth_table->count; i++)
		seq_printf(file, "%d: %u %u %u %u %u %u %pM %s %d %d %d\n",
			   i, eth_table->ports[i].eth_index,
			   eth_table->ports[i].index,
			   eth_table->ports[i].nbi,
			   eth_table->ports[i].base,
			   eth_table->ports[i].lanes,
			   eth_table->ports[i].speed,
			   eth_table->ports[i].mac_addr,
			   eth_table->ports[i].label,
			   eth_table->ports[i].enabled,
			   eth_table->ports[i].tx_enabled,
			   eth_table->ports[i].rx_enabled);

	nfp_cpp_free(cpp);
	return 0;
}

static int nth_eth_table_open(struct inode *inode, struct file *f)
{
	return single_open(f, nth_eth_table_read, inode->i_private);
}

static const struct file_operations nth_eth_table_ops = {
	.owner = THIS_MODULE,
	.open = nth_eth_table_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek,
};

static ssize_t
nth_write_eth_enable(struct file *file, const char __user *user_buf,
		     size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	unsigned int idx, enable;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	int err, srcu_idx;
	ssize_t ret;

	ret = debugfs_use_file_start(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	debugfs_use_file_finish(srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	if (sscanf(data, "%u %u", &idx, &enable) != 2)
		return -EINVAL;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	err = nfp_eth_set_mod_enable(cpp, idx, enable);
	if (err)
		ret = err;

	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_eth_enable_ops = {
	.read = nth_read_blob,
	.write = nth_write_eth_enable,
	.open = simple_open,
	.llseek = default_llseek,
};

static int __init nth_init(void)
{
	bool fail = false;

	nth.dir = debugfs_create_dir("nth", NULL);
	if (!nth.dir)
		return -EBUSY;

	fail |= !debugfs_create_u8("id", 0600, nth.dir, &nth.id);

	fail |= !debugfs_create_file("reset", 0400, nth.dir,
				     NULL, &nth_reset_ops);

	fail |= !debugfs_create_file("serial", 0400, nth.dir,
				     NULL, &nth_serial_ops);
	fail |= !debugfs_create_file("interface", 0400, nth.dir,
				     NULL, &nth_interface_ops);

	fail |= !debugfs_create_file("hwinfo_key", 0600, nth.dir,
				     &nth.hwinfo_key, &nth_hwinfo_ops);
	fail |= !debugfs_create_blob("hwinfo_val", 0400, nth.dir,
				     &nth.hwinfo_val);

	fail |= !debugfs_create_file("cache_flush", 0400, nth.dir,
				     NULL, &nth_cache_flush_ops);
	fail |= !debugfs_create_file("rtsym_count", 0400, nth.dir,
				     NULL, &nth_rtsym_count_ops);
	fail |= !debugfs_create_file("rtsym_dump", 0400, nth.dir,
				     NULL, &nth_rtsym_dump_ops);
	fail |= !debugfs_create_file("rtsym_key", 0600, nth.dir,
				     &nth.rtsym_key, &nth_rtsym_ops);
	fail |= !debugfs_create_blob("rtsym_val", 0400, nth.dir,
				     &nth.rtsym_val);

	fail |= !debugfs_create_file("fw_load", 0600, nth.dir,
				     &nth.fw_load, &nth_fw_load_ops);

	fail |= !debugfs_create_file("resource", 0600, nth.dir,
				     NULL, &nth_resource_ops);

	fail |= !debugfs_create_file("eth_table", 0400, nth.dir,
				     NULL, &nth_eth_table_ops);
	fail |= !debugfs_create_file("eth_enable", 0600, nth.dir,
				     &nth.wr_only, &nth_eth_enable_ops);

	if (fail) {
		debugfs_remove_recursive(nth.dir);
		return -EINVAL;
	}

	return 0;
}

static void __exit nth_exit(void)
{
	int i;

	debugfs_remove_recursive(nth.dir);

	for (i = 0; i < ARRAY_SIZE(nth.resources); i++) {
		if (!nth.resources[i].name)
			continue;
		kfree(nth.resources[i].name);
		nfp_resource_release(nth.resources[i].res);
	}
}

module_init(nth_init);
module_exit(nth_exit);

MODULE_AUTHOR("Netronome Systems <oss-drivers@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The Netronome Flow Processor (NFP) test harness.");
