// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2016-2018 Netronome Systems, Inc. */

#include "nfp_net_compat.h"

#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "nfp_main.h"
#include "nfpcore/nfp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp.h"
#include "nfpcore/nfp6000/nfp6000.h"
#include "nfp_test_harness.h"

#define NTH_MAX_DUMPSPEC_SIZE	10240

struct nth nth = {
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
			goto exit_free_cpp;				\
		}							\
									\
		ret = __op(nsp);					\
									\
		nfp_nsp_close(nsp);					\
	exit_free_cpp:							\
		nfp_cpp_free(cpp);					\
									\
		return ret;						\
	}								\
	NTH_DECLARE_HANDLER(__name);

static int nth_dfs_file_get(struct dentry *dentry, int *srcu_idx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	return debugfs_file_get(dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	return debugfs_use_file_start(dentry, srcu_idx);
#else
	return 0;
#endif
}

static void nth_dfs_file_put(struct dentry *dentry, int srcu_idx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	debugfs_file_put(dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	debugfs_use_file_finish(srcu_idx);
#endif
}

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
		goto exit_free;
	}

	seq_printf(file, "%pM", serial);
exit_free:
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

NTH_DECLARE_ACTION_NSP(reset, nfp_nsp_device_soft_reset);

static int nth_rtsym_count_read(struct seq_file *file, void *data)
{
	struct nfp_rtsym_table *rtbl;
	struct nfp_cpp *cpp;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	rtbl = nfp_rtsym_table_read(cpp);

	seq_printf(file, "%d\n", nfp_rtsym_count(rtbl));

	kfree(rtbl);
	nfp_cpp_free(cpp);

	return 0;
}
NTH_DECLARE_HANDLER(rtsym_count);

static int nth_rtsym_dump_read(struct seq_file *file, void *data)
{
	const struct nfp_rtsym *rtsym;
	struct nfp_rtsym_table *rtbl;
	struct nfp_cpp *cpp;
	int i;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	rtbl = nfp_rtsym_table_read(cpp);

	i = 0;
	while ((rtsym = nfp_rtsym_get(rtbl, i++)))
		seq_printf(file, "%s\n", rtsym->name);

	kfree(rtbl);
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

	mutex_lock(&nth.lock);
	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_read_from_buffer(user_buf, count, ppos,
					      blob->data, blob->size);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	mutex_unlock(&nth.lock);

	return ret;
}

static ssize_t nth_write_hwinfo(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	u8 *data = blob->data, *tmp_buf = NULL;
	struct nfp_hwinfo *hwinfo = NULL;
	struct nfp_cpp *cpp;
	const char *value;
	ssize_t ret, len;
	int srcu_idx;

	mutex_lock(&nth.lock);

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		goto exit_unlock;
	len = ret;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp) {
		ret = -EBUSY;
		goto exit_unlock;
	}

	memset(nth.hwinfo_val_data, 0, sizeof(nth.hwinfo_val_data));

	if (nth.hwinfo_static_db) {
		data[len] = 0;
		hwinfo = nfp_hwinfo_read(cpp);
		value = nfp_hwinfo_lookup(hwinfo, data);
		if (!value) {
			ret = -EINVAL;
			goto exit_free;
		}
	} else { /* Indirect access via the NSP */
		struct nfp_nsp *nsp;

		tmp_buf = kmemdup(data, len, GFP_KERNEL);
		if (!tmp_buf) {
			ret = -ENOMEM;
			goto exit_free;
		}

		nsp = nfp_nsp_open(cpp);
		ret = PTR_ERR_OR_ZERO(nsp);
		if (ret)
			goto exit_free;

		ret = nfp_nsp_hwinfo_lookup(nsp, tmp_buf, len);
		nfp_nsp_close(nsp);
		if (ret)
			goto exit_free;

		ret = len;
		value = tmp_buf;
	}

	memcpy(nth.hwinfo_val_data, value,
	       strnlen(value, sizeof(nth.hwinfo_val_data)));

exit_free:
	kfree(tmp_buf);
	kfree(hwinfo);
	nfp_cpp_free(cpp);
exit_unlock:
	mutex_unlock(&nth.lock);

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
	struct nfp_rtsym_table *rtbl;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	int srcu_idx;
	ssize_t ret;

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	rtbl = nfp_rtsym_table_read(cpp);
	value = nfp_rtsym_lookup(rtbl, data);
	if (!value)
		ret = -ENOENT;

	kfree(rtbl);
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_rtsym_ops = {
	.read = nth_read_blob,
	.write = nth_write_rtsym,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t
nth_read_rtsym_val(struct file *file, char __user *user_buf,
		   size_t count, loff_t *ppos)
{
	struct nfp_rtsym_table *rtbl;
	const struct nfp_rtsym *sym;
	struct nfp_cpp *cpp;
	int srcu_idx;
	ssize_t ret;
	u8 *buf;

	mutex_lock(&nth.lock);
	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (ret)
		goto exit_unlock;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp) {
		ret = -EBUSY;
		goto exit_dfs_put;
	}

	buf = kmalloc(count, GFP_USER);
	if (!buf) {
		ret = -ENOMEM;
		goto exit_free_cpp;
	}

	rtbl = nfp_rtsym_table_read(cpp);
	sym = nfp_rtsym_lookup(rtbl, nth.rtsym_key.data);
	if (sym) {
		ret = nfp_rtsym_read(cpp, sym, *ppos, buf, count);
	} else {
		ret = -ENOENT;
		goto exit_free_rtbl;
	}

	if (ret > 0) {
		if (copy_to_user(user_buf, buf, ret))
			ret = -EFAULT;
		else
			*ppos += ret;
	}

exit_free_rtbl:
	kfree(rtbl);
	kfree(buf);
exit_free_cpp:
	nfp_cpp_free(cpp);
exit_dfs_put:
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
exit_unlock:
	mutex_unlock(&nth.lock);

	return ret;
}

static ssize_t
nth_write_rtsym_val(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	struct nfp_rtsym_table *rtbl;
	const struct nfp_rtsym *sym;
	struct nfp_cpp *cpp;
	int srcu_idx;
	ssize_t ret;
	u8 *buf;

	mutex_lock(&nth.lock);
	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (ret)
		goto exit_unlock;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp) {
		ret = -EBUSY;
		goto exit_dfs_put;
	}

	buf = kmalloc(count, GFP_USER);
	if (!buf) {
		ret = -ENOMEM;
		goto exit_free_cpp;
	}
	if (copy_from_user(buf, user_buf, count)) {
		ret = -EFAULT;
		goto exit_free_buf;
	}

	rtbl = nfp_rtsym_table_read(cpp);
	sym = nfp_rtsym_lookup(rtbl, nth.rtsym_key.data);
	if (sym) {
		ret = nfp_rtsym_write(cpp, sym, *ppos, buf, count);
	} else {
		ret = -ENOENT;
		goto exit_free_rtbl;
	}

	if (ret > 0)
		*ppos += ret;

exit_free_rtbl:
	kfree(rtbl);
exit_free_buf:
	kfree(buf);
exit_free_cpp:
	nfp_cpp_free(cpp);
exit_dfs_put:
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
exit_unlock:
	mutex_unlock(&nth.lock);

	return ret;
}

static const struct file_operations nth_rtsym_val_ops = {
	.read	= nth_read_rtsym_val,
	.write	= nth_write_rtsym_val,
	.open	= simple_open,
	.llseek	= default_llseek,
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

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;
	copied = ret;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	ret = request_firmware(&fw, data, nfp_cpp_device(cpp)->parent);
	if (ret < 0)
		goto exit_free_cpp;

	nsp = nfp_nsp_open(cpp);
	if (IS_ERR(nsp)) {
		ret = PTR_ERR(nsp);
		goto exit_release_fw;
	}

	ret = nfp_nsp_wait(nsp);
	if (ret < 0)
		goto exit_nsp_close;

	ret = nfp_nsp_device_soft_reset(nsp);
	if (ret < 0) {
		pr_err("Failed to soft reset the NFP: %zd\n", ret);
		goto exit_nsp_close;
	}

	ret = nfp_nsp_load_fw(nsp, fw);
	if (ret) {
		pr_err("FW loading failed: %zd\n", ret);
		goto exit_nsp_close;
	}

exit_nsp_close:
	nfp_nsp_close(nsp);
exit_release_fw:
	release_firmware(fw);
exit_free_cpp:
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

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(name, sizeof(name) - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	copied = ret;
	ret = 0;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	if (kstrtol(name, 0, &i)) {
		char *new_name;

		mutex_lock(&nth.lock);
		for (i = 0; i < ARRAY_SIZE(nth.resources); i++)
			if (!nth.resources[i].res)
				break;
		if (i == ARRAY_SIZE(nth.resources)) {
			mutex_unlock(&nth.lock);
			ret = -ENOSPC;
			goto exit_free_cpp;
		}
		/* mark as used until we get a full pointer or fail and clear */
		nth.resources[i].res = (void *)1;
		mutex_unlock(&nth.lock);

		new_name = kstrdup(name, GFP_KERNEL);
		if (!new_name) {
			ret = -ENOMEM;
			memset(&nth.resources[i], 0, sizeof(nth.resources[i]));
			goto exit_free_cpp;
		}

		nth.resources[i].res = nfp_resource_acquire(cpp, name);
		if (IS_ERR(nth.resources[i].res)) {
			kfree(new_name);
			ret = PTR_ERR(nth.resources[i].res);
			memset(&nth.resources[i], 0, sizeof(nth.resources[i]));
			goto exit_free_cpp;
		}
		nth.resources[i].name = new_name;
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

	for (i = 0; i < eth_table->count; i++) {
		seq_printf(file, "%d: %u %u %u %u %u %u %pM %d.%d %d %d %d ",
			   i, eth_table->ports[i].eth_index,
			   eth_table->ports[i].index,
			   eth_table->ports[i].nbi,
			   eth_table->ports[i].base,
			   eth_table->ports[i].lanes,
			   eth_table->ports[i].speed,
			   eth_table->ports[i].mac_addr,
			   eth_table->ports[i].label_port,
			   eth_table->ports[i].label_subport,
			   eth_table->ports[i].enabled,
			   eth_table->ports[i].tx_enabled,
			   eth_table->ports[i].rx_enabled);

		seq_printf(file, "| %d %d %d %d ",
			   eth_table->ports[i].interface,
			   eth_table->ports[i].media,
			   eth_table->ports[i].aneg,
			   eth_table->ports[i].override_changed);

		seq_printf(file, "| 0x%02hhx %d\n",
			   eth_table->ports[i].port_type,
			   eth_table->ports[i].is_split);
	}

	kfree(eth_table);
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

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
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

static ssize_t
nth_write_eth_aneg(struct file *file, const char __user *user_buf,
		   size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	unsigned int idx, aneg;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	struct nfp_nsp *nsp;
	int err, srcu_idx;
	ssize_t ret;

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	if (sscanf(data, "%u %u", &idx, &aneg) != 2)
		return -EINVAL;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	nsp = nfp_eth_config_start(cpp, idx);
	if (IS_ERR(nsp)) {
		ret = PTR_ERR(nsp);
		goto err;
	}

	__nfp_eth_set_aneg(nsp, aneg);
	err = nfp_eth_config_commit_end(nsp);
	if (err)
		ret = err;
err:
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_eth_aneg_ops = {
	.read = nth_read_blob,
	.write = nth_write_eth_aneg,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t
nth_write_eth_speed(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	unsigned int idx, speed;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	struct nfp_nsp *nsp;
	int err, srcu_idx;
	ssize_t ret;

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	if (sscanf(data, "%u %u", &idx, &speed) != 2)
		return -EINVAL;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	nsp = nfp_eth_config_start(cpp, idx);
	if (IS_ERR(nsp)) {
		ret = PTR_ERR(nsp);
		goto err;
	}

	__nfp_eth_set_speed(nsp, speed);
	err = nfp_eth_config_commit_end(nsp);
	if (err)
		ret = err;
err:
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_eth_speed_ops = {
	.read = nth_read_blob,
	.write = nth_write_eth_speed,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t
nth_write_eth_lanes(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	unsigned int idx, lanes;
	u8 *data = blob->data;
	struct nfp_cpp *cpp;
	struct nfp_nsp *nsp;
	int err, srcu_idx;
	ssize_t ret;

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, blob->size - 1,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);
	if (ret < 0)
		return ret;
	data[ret] = 0;

	if (sscanf(data, "%u %u", &idx, &lanes) != 2)
		return -EINVAL;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	nsp = nfp_eth_config_start(cpp, idx);
	if (IS_ERR(nsp)) {
		ret = PTR_ERR(nsp);
		goto err;
	}

	__nfp_eth_set_split(nsp, lanes);
	err = nfp_eth_config_commit_end(nsp);
	if (err)
		ret = err;
err:
	nfp_cpp_free(cpp);

	return ret;
}

static const struct file_operations nth_eth_lanes_ops = {
	.read = nth_read_blob,
	.write = nth_write_eth_lanes,
	.open = simple_open,
	.llseek = default_llseek,
};

static struct nfp_pf *nth_get_dump_pf(struct nfp_cpp *cpp)
{
	struct nfp_pf *pf = kzalloc(sizeof(*pf), GFP_KERNEL);

	pf->cpp = cpp;
	pf->rtbl = nfp_rtsym_table_read(cpp);
	if (!pf->rtbl)
		return NULL;

	pf->mip = nfp_mip_open(cpp);
	if (!pf->mip)
		return NULL;

	pf->hwinfo = nfp_hwinfo_read(cpp);
	if (!pf->hwinfo)
		return NULL;

	return pf;
}

static void nth_free_dump_pf(struct nfp_pf *pf)
{
	kfree(pf->rtbl);
	kfree(pf->hwinfo);
	nfp_mip_close(pf->mip);
	kfree(pf);
}

static int nth_create_private_wrapper(struct file *file, int data_size,
				      void *source)
{
	struct debugfs_blob_wrapper *wrapper;

	wrapper = kmalloc(sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper)
		return -ENOMEM;

	wrapper->data = vmalloc(data_size);
	if (!wrapper->data) {
		kfree(wrapper);
		return -ENOMEM;
	}

	/* If source is given, make a copy and set the size, otherwise
	 * use size to track bytes written.
	 */
	if (source) {
		wrapper->size = data_size;
		memcpy(wrapper->data, source, data_size);
	} else {
		wrapper->size = 0;
	}
	file->private_data = wrapper;

	return 0;
}

static int nth_free_private_wrapper(struct inode *inode, struct file *file)
{
	struct debugfs_blob_wrapper *wrapper = file->private_data;

	vfree(wrapper->data);
	kfree(wrapper);

	return 0;
}

static int nth_fwdump_spec_open(struct inode *inode, struct file *file)
{
	return nth_create_private_wrapper(file, NTH_MAX_DUMPSPEC_SIZE, NULL);
}

static ssize_t
nth_fwdump_spec_write(struct file *file, const char __user *user_buf,
		      size_t count, loff_t *ppos)
{
	struct debugfs_blob_wrapper *blob = file->private_data;
	int srcu_idx;
	ssize_t ret;

	ret = nth_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (likely(!ret))
		ret = simple_write_to_buffer(blob->data, NTH_MAX_DUMPSPEC_SIZE,
					     ppos, user_buf, count);
	nth_dfs_file_put(file->f_path.dentry, srcu_idx);

	/* blob->size tracks the total number of bytes written */
	if (ret > 0)
		blob->size += ret;

	return ret;
}

/* In mutex, replace the global dumpspec data with the one written to this file.
 */
static int nth_fwdump_spec_close(struct inode *inode, struct file *file)
{
	struct debugfs_blob_wrapper *wrapper = file->private_data;

	mutex_lock(&nth.lock);
	vfree(nth.dumpspec.data);
	nth.dumpspec.data = wrapper->data;
	nth.dumpspec.size = wrapper->size;
	mutex_unlock(&nth.lock);

	kfree(wrapper);

	return 0;
}

static const struct file_operations nth_fwdump_spec_ops = {
	.open = nth_fwdump_spec_open,
	.write = nth_fwdump_spec_write,
	.release = nth_fwdump_spec_close,
	.llseek = default_llseek,
};

static struct nfp_dumpspec *nth_create_dumpspec(void *data, u32 size)
{
	struct nfp_dumpspec *dumpspec;

	dumpspec = vmalloc(sizeof(*dumpspec) + size);
	if (!dumpspec)
		return NULL;

	dumpspec->size = size;
	memcpy(dumpspec->data, data, size);

	return dumpspec;
}

static int nth_fwdump_trigger_read(struct seq_file *file, void *data)
{
	struct nfp_dumpspec *dumpspec = NULL;
	struct ethtool_dump dump_param;
	struct nfp_cpp *cpp;
	s64 calculated_len;
	struct nfp_pf *pf;
	u32 dump_level;
	void *dump;
	int err;

	cpp = nfp_cpp_from_device_id(nth.id);
	if (!cpp)
		return -EBUSY;

	pf = nth_get_dump_pf(cpp);
	dump_level = READ_ONCE(nth.dump_level);
	if (!pf || !dump_level) {
		err = -EOPNOTSUPP;
		goto exit_free_cpp;
	}

	/* In mutex, copy dumpspec from global dumpspec data wrapper. */
	mutex_lock(&nth.lock);
	if (nth.dumpspec.data)
		dumpspec = nth_create_dumpspec(nth.dumpspec.data,
					       nth.dumpspec.size);
	mutex_unlock(&nth.lock);

	if (!dumpspec) {
		err = -EINVAL;
		goto exit_free_cpp;
	}

	calculated_len = nfp_net_dump_calculate_size(pf, dumpspec, dump_level);
	if (calculated_len < 0) {
		err = calculated_len;
		goto exit_free_cpp;
	}

	dump = vzalloc(calculated_len);
	if (!dump) {
		err = -ENOMEM;
		goto exit_free_cpp;
	}

	dump_param.flag = dump_level;
	dump_param.len = calculated_len;

	/* Lock with the same rtnl_lock used by ethtool to protect its ops,
	 * to avoid issues with concurrent dumps between tests and ethtool,
	 * e.g. concurrent reads of indirect ME CSRs.
	 */
	rtnl_lock();
	err = nfp_net_dump_populate_buffer(pf, dumpspec, &dump_param, dump);
	rtnl_unlock();

	/* In a mutex, set/replace the global fw dump data. */
	mutex_lock(&nth.lock);
	vfree(nth.fwdump.data);
	nth.fwdump.data = dump;
	nth.fwdump.size = dump_param.len;
	/* Size could change duing populate, warn the user if this happens. */
	if (nth.fwdump.size != calculated_len)
		err = -EMSGSIZE;
	mutex_unlock(&nth.lock);

exit_free_cpp:
	nfp_cpp_free(cpp);
	nth_free_dump_pf(pf);
	vfree(dumpspec);
	seq_printf(file, "%d\n", err);

	return 0;
}
NTH_DECLARE_HANDLER(fwdump_trigger);

/* In mutex, create a copy of the global dump data, for this file's
 * private_data.
 */
static int nth_fwdump_open(struct inode *inode, struct file *file)
{
	int ret;

	mutex_lock(&nth.lock);
	if (!nth.fwdump.data) {
		ret = -ENOENT;
		goto exit_unlock;
	}
	ret = nth_create_private_wrapper(file, nth.fwdump.size,
					 nth.fwdump.data);

exit_unlock:
	mutex_unlock(&nth.lock);

	return ret;
}

static const struct file_operations nth_fwdump_data_ops = {
	.read = nth_read_blob,
	.open = nth_fwdump_open,
	.release = nth_free_private_wrapper,
	.llseek = default_llseek,
};

static int __init nth_init(void)
{
	bool fail = false;

	INIT_LIST_HEAD(&nth.rand);
	mutex_init(&nth.lock);

	nth.dir = debugfs_create_dir("nth", NULL);
	if (!nth.dir)
		return -EBUSY;

	debugfs_create_u8("id", 0600, nth.dir, &nth.id);

	fail |= !debugfs_create_file("reset", 0400, nth.dir,
				     NULL, &nth_reset_ops);

	fail |= !debugfs_create_file("serial", 0400, nth.dir,
				     NULL, &nth_serial_ops);
	fail |= !debugfs_create_file("interface", 0400, nth.dir,
				     NULL, &nth_interface_ops);

	nth.hwinfo_static_db = true;
	fail |= !debugfs_create_bool("hwinfo_static_db", 0600, nth.dir,
				     &nth.hwinfo_static_db);
	fail |= !debugfs_create_file("hwinfo_key", 0600, nth.dir,
				     &nth.hwinfo_key, &nth_hwinfo_ops);
	fail |= !debugfs_create_blob("hwinfo_val", 0400, nth.dir,
				     &nth.hwinfo_val);

	fail |= !debugfs_create_u32("fw_dump_level", 0600, nth.dir,
				    &nth.dump_level);
	fail |= !debugfs_create_file("fw_dump_spec", 0200, nth.dir, NULL,
				     &nth_fwdump_spec_ops);
	fail |= !debugfs_create_file("fw_dump_trigger", 0400, nth.dir, NULL,
				     &nth_fwdump_trigger_ops);
	fail |= !debugfs_create_file("fw_dump_data", 0400, nth.dir, NULL,
				     &nth_fwdump_data_ops);

	fail |= !debugfs_create_file("rtsym_count", 0400, nth.dir,
				     NULL, &nth_rtsym_count_ops);
	fail |= !debugfs_create_file("rtsym_dump", 0400, nth.dir,
				     NULL, &nth_rtsym_dump_ops);
	fail |= !debugfs_create_file("rtsym_key", 0600, nth.dir,
				     &nth.rtsym_key, &nth_rtsym_ops);
	fail |= !debugfs_create_file("rtsym_val", 0600, nth.dir,
				     NULL, &nth_rtsym_val_ops);

	fail |= !debugfs_create_file("fw_load", 0600, nth.dir,
				     &nth.fw_load, &nth_fw_load_ops);

	fail |= !debugfs_create_file("resource", 0600, nth.dir,
				     NULL, &nth_resource_ops);

	fail |= !debugfs_create_file("eth_table", 0400, nth.dir,
				     NULL, &nth_eth_table_ops);
	fail |= !debugfs_create_file("eth_enable", 0600, nth.dir,
				     &nth.wr_only, &nth_eth_enable_ops);
	fail |= !debugfs_create_file("eth_aneg", 0600, nth.dir,
				     &nth.wr_only, &nth_eth_aneg_ops);
	fail |= !debugfs_create_file("eth_speed", 0600, nth.dir,
				     &nth.wr_only, &nth_eth_speed_ops);
	fail |= !debugfs_create_file("eth_lanes", 0600, nth.dir,
				     &nth.wr_only, &nth_eth_lanes_ops);

	fail |= !debugfs_create_file("rand_r", 0600, nth.dir,
				     NULL, &nth_rand_r_ops);
	fail |= !debugfs_create_bool("rand_trigger_warns", 0600, nth.dir,
				     &nth.rand_trigger_warns);

	if (fail) {
		debugfs_remove_recursive(nth.dir);
		return -EINVAL;
	}

	return 0;
}

static void __exit nth_exit(void)
{
	int i;

	mutex_destroy(&nth.lock);
	debugfs_remove_recursive(nth.dir);

	for (i = 0; i < ARRAY_SIZE(nth.resources); i++) {
		if (!nth.resources[i].name)
			continue;
		kfree(nth.resources[i].name);
		nfp_resource_release(nth.resources[i].res);
	}

	vfree(nth.dumpspec.data);
	vfree(nth.fwdump.data);
}

module_init(nth_init);
module_exit(nth_exit);

MODULE_AUTHOR("Netronome Systems <oss-drivers@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The Netronome Flow Processor (NFP) test harness.");
