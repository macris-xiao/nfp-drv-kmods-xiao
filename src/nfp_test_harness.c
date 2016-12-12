/*
 * Copyright (C) 2016 Netronome Systems, Inc.
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
NTH_DECLARE_ACTION(reset, nfp_reset_soft);

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
	int timeout = 30;
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

	for (; timeout > 0; timeout--) {
		ret = nfp_nsp_command(nsp, SPCODE_NOOP, 0, 0, 0);
		if (ret != -EAGAIN)
			break;
		if (msleep_interruptible(1000) > 0) {
			ret = -ETIMEDOUT;
			break;
		}
	}
	if (ret < 0) {
		pr_err("NSP failed to respond\n");
		goto err_nsp_close;
	}

	ret = nfp_reset_soft(cpp);
	if (ret < 0) {
		pr_err("Failed to soft reset the NFP: %ld\n", ret);
		goto err_nsp_close;
	}

	/* Lock the NFP, prevent others from touching it while we
	 * load the firmware.
	 */
	ret = nfp_device_lock(cpp);
	if (ret < 0) {
		pr_err("Can't lock NFP device: %ld\n", ret);
		goto err_nsp_close;
	}

	ret = nfp_ca_replay(cpp, fw->data, fw->size);
	nfp_device_unlock(cpp);

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

	if (fail) {
		debugfs_remove_recursive(nth.dir);
		return -EINVAL;
	}

	return 0;
}

static void __exit nth_exit(void)
{
	debugfs_remove_recursive(nth.dir);
}

module_init(nth_init);
module_exit(nth_exit);

MODULE_AUTHOR("Netronome Systems <oss-drivers@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The Netronome Flow Processor (NFP) test harness.");
