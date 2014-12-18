/* Copyright (C) 2011 Netronome Systems, Inc. All rights reserved.
 *
 * This software may be redistributed under either of two provisions:
 *
 * 1. The GNU General Public License version 2 (see
 *    http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
 *    COPYING.txt file) when it is used for Linux or other
 *    compatible free software as defined by GNU at
 *    http://www.gnu.org/licenses/license-list.html.
 *
 * 2. Or under a non-free commercial license executed directly with
 *    Netronome. The direct Netronome license does not apply when the
 *    software is used as part of the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Parses the hwinfo table that the ARM firmware builds in the ARM scratch SRAM
 * after chip reset.
 *
 * Some of the fields:
 *   me.count = 40
 *   me.mask = 0x7f_ffff_ffff
 *
 *   me.count is the total number of MEs on the system.
 *   me.mask is the bitmask of MEs that are available for application usage.
 *
 *   (ie, in this example, ME 39 has been reserved by boardconfig.)
 *
 *   arm.mem = 512
 *   assembly.model = rsvp
 *   board.exec = linux.bin
 *   board.setup = boardconfig.bin
 *   chip.model = NFP3240
 *   config.timestamp = 2010-1-5 17:58:22 GMT
 *   ddr.mem = 2048
 *   flash.model = tip
 *   me.mem = 1536
 *   qdr1.enabled = 1
 *   qdr1.mem = 8
 *   qdr1.type = mem
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/log2.h>
#include <linux/crc32.h>
#include <linux/delay.h>

#include "nfp.h"

#include "nfp_resource.h"
#include "nfp-bsp/nfp_resource.h"
#include "nfp-bsp/nfp_hwinfo.h"
#include "nfp_cpp_kernel.h"
#include "nfp3200/nfp3200.h"
#include "nfp3200/nfp_xpb.h"
#include "nfp3200/nfp_pl.h"

#include "nfp_common.h"
#include "nfp_device.h"

#define HWINFO_SIZE_MIN	0x100

#undef NFP_SUBSYS
#define NFP_SUBSYS "[HWINFO] "

static int hwinfo_wait = 15;	/* 15 seconds */
module_param(hwinfo_wait, int, S_IRUGO);
MODULE_PARM_DESC(hwinfo_wait, "-1 for no timeout, or N seconds to wait for board.state match");

static int hwinfo_debug;
module_param(hwinfo_debug, int, S_IRUGO);
MODULE_PARM_DESC(hwinfo_debug, "Enable to log hwinfo contents on load");

#define NFP_HWINFO_DEBUG	hwinfo_debug

/* NOTE: This should be 15 (SKUSE_POWER)
 */
static int board_state = 15;	/* board.state to match against */
module_param(board_state, int, S_IRUGO);
MODULE_PARM_DESC(board_state, "board.state to wait for");

static void hwinfo_db_parse(struct nfp_device *nfp)
{
	const char *key;
	const char *val;

	for (key = NFP_HWINFO_DATA_START(nfp->hwinfo);
	     *key && key < (const char *)NFP_HWINFO_DATA_END(nfp->hwinfo);
	     key = val + strlen(val) + 1) {
		val = key + strlen(key) + 1;

		nfp_dbg(nfp, "%s=%s\n", key, val);
	}
}

static u32 hwinfo_crc(void *db)
{
	u32 crc;
	u32 len = NFP_HWINFO_SIZE_in(db) - sizeof(u32);

	crc = crc32_be(0, db, len);

	/* Extend with the length of the string (but not the length word). */
	while (len != 0) {
		uint8_t byte = len & 0xff;

		crc = crc32_be(crc, (void *)&byte, 1);
		len >>= 8;
	}

	return ~crc;
}

static int hwinfo_db_validate(struct nfp_device *nfp, void *db, u32 len)
{
	u32 crc;

	if (NFP_HWINFO_VERSION_in(db) != NFP_HWINFO_VERSION_1 &&
	    NFP_HWINFO_VERSION_in(db) != NFP_HWINFO_VERSION_2) {
		nfp_err(nfp, "Unknown hwinfo version 0x%x, expected 0x%x or 0x%x\n",
			NFP_HWINFO_VERSION_in(db),
			NFP_HWINFO_VERSION_1, NFP_HWINFO_VERSION_2);
		return -EINVAL;
	}

	if (NFP_HWINFO_SIZE_in(db) > len) {
		nfp_err(nfp, "Unsupported hwinfo size %u > %u\n",
			NFP_HWINFO_SIZE_in(db), len);
		return -EINVAL;
	}

	crc = hwinfo_crc(db);
	if (crc != NFP_HWINFO_CRC32_in(db)) {
		nfp_err(nfp, "Corrupt hwinfo table (CRC mismatch), calculated 0x%x, expected 0x%x\n",
			crc, NFP_HWINFO_CRC32_in(db));
		return -EINVAL;
	}

	return 0;
}

static int hwinfo_fetch(struct nfp_device *nfp, void **hwdb, size_t *hwdb_size)
{
	struct nfp_cpp_area *area;
	int r = 0;
	int timeout = hwinfo_wait;
	uint32_t cpp_id;
	uint64_t cpp_addr;
	size_t   cpp_size;
	void *tmpdb;
	struct nfp_resource *res;

	res = nfp_resource_acquire(nfp, NFP_RESOURCE_NFP_HWINFO);
	if (res) {
		cpp_id = nfp_resource_cpp_id(res);
		cpp_addr = nfp_resource_address(res);
		cpp_size = nfp_resource_size(res);

		nfp_resource_release(res);

		if (cpp_size < HWINFO_SIZE_MIN)
			return -ENOENT;
	} else {
		/* Try getting the HWInfo table from the 'classic' location
		 */
		cpp_id = NFP_CPP_ID(NFP_CPP_TARGET_ARM_SCRATCH,
				    NFP_CPP_ACTION_RW, 0);
		cpp_addr = 0;
		cpp_size = 2 * 1024;
	}

	/* Fetch the hardware table from the ARM's SRAM (scratch).  It
	 * occupies 0x0000 - 0x1fff.
	 */
	area = nfp_cpp_area_alloc_with_name(nfp->cpp, cpp_id, "nfp.hwinfo",
					    cpp_addr, cpp_size);
	if (!area)
		return -EIO;
	if (nfp_cpp_area_acquire(area) < 0) {
		nfp_cpp_area_free(area);
		return -EIO;
	}

	tmpdb = kmalloc(cpp_size, GFP_KERNEL);
	if (tmpdb == NULL) {
		nfp_cpp_area_release_free(area);
		return -ENOMEM;
	}

	memset(tmpdb, 0xff, cpp_size);

	/* Wait for the hwinfo table to become available
	 */
	for (timeout = (hwinfo_wait * 10); timeout >= 0; timeout--) {
		uint32_t ver;
		uint8_t header[16];

		r = nfp_cpp_area_read(area, 0, header, sizeof(header));
		if (r < 0) {
			nfp_err(nfp, "Can't read version: %d\n", r);
			break;
		}

		ver = NFP_HWINFO_VERSION_in(header);

		if (NFP_HWINFO_VERSION_UPDATING(ver))
			continue;

		if (ver == NFP_HWINFO_VERSION_2 || ver == NFP_HWINFO_VERSION_1)
			break;

		msleep(100);	/* Sleep for 1/10 second. */
	}

	if (r < 0) {
		nfp_err(nfp, "NFP access error detected\n");
	} else if (hwinfo_wait >= 0 && timeout < 0) {
		nfp_err(nfp, "Timed out after %d seconds, waiting for HWInfo\n",
			hwinfo_wait);
		r = -EIO;
	}

	if (r >= 0) {
		r = nfp_cpp_area_read(area, 0, tmpdb, cpp_size);
		if (r >= 0 && r != cpp_size)
			r = -EIO;

		if (r >= 0) {
			*hwdb = tmpdb;
			*hwdb_size = cpp_size;
		}
	}

	if (r < 0)
		kfree(tmpdb);

	nfp_cpp_area_release_free(area);

	return r;
}

const char *nfp_hwinfo_lookup(struct nfp_device *nfp, const char *lookup)
{
	const char *val = NULL;

	/* This must only be called after nfp_hwinfo_init()
	 * has returned.
	 */

	if (nfp->hwinfo && lookup) {
		const char *key;

		for (key = NFP_HWINFO_DATA_START(nfp->hwinfo);
			*key &&
			key < (const char *)NFP_HWINFO_DATA_END(nfp->hwinfo);
			key = val + strlen(val) + 1, val = NULL) {
			val = key + strlen(key) + 1;

			if (strcmp(key, lookup) == 0)
				break;
		}
	}

	return val;
}

int nfp_hwinfo_init(struct nfp_device *nfp)
{
	void *hwdb = NULL;
	size_t hwdb_size = 0;
	int r = 0;
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	uint32_t model;

	if (nfp->hwinfo)
		return 0;

	model = nfp_cpp_model(cpp);

	if (NFP_CPP_MODEL_IS_3200(model) &&
	    NFP_CPP_INTERFACE_TYPE_of(nfp_cpp_interface(nfp->cpp)) ==
	       NFP_CPP_INTERFACE_TYPE_PCI) {
		u32 straps;
		u32 pl_re;
		u32 arm_re;

		r = nfp_xpb_readl(nfp->cpp, NFP_XPB_PL|NFP_PL_STRAPS, &straps);
		if (r < 0) {
			nfp_err(nfp, "nfp_xpb_readl failed().\n");
			r = -ENODEV;
			goto err;
		}
		r = nfp_xpb_readl(nfp->cpp, NFP_XPB_PL|NFP_PL_RE, &pl_re);
		if (r < 0) {
			nfp_err(nfp, "nfp_xpb_readl failed().\n");
			r = -ENODEV;
			goto err;
		}
		arm_re = NFP_PL_RE_ARM_GASKET_RESET|NFP_PL_RE_ARM_GASKET_ENABLE;
		if (((straps & NFP_PL_STRAPS_CFG_PROM_BOOT) == 0) &&
		    ((pl_re & arm_re) != arm_re)) {
			nfp_err(nfp, "ARM gasket is disabled.\n");
			r = -ENODEV;
			goto err;
		}
	}

	r = hwinfo_fetch(nfp, &hwdb, &hwdb_size);
	if (r < 0)
		goto err;

	r = hwinfo_db_validate(nfp, hwdb, hwdb_size);
	if (r < 0)
		goto err;

	nfp->hwinfo = hwdb;
	if (NFP_HWINFO_DEBUG)
		hwinfo_db_parse(nfp);

err:
	if (r < 0) {
		kfree(hwdb);
		nfp->hwinfo = NULL;
	}

	return r;
}

void nfp_hwinfo_cleanup(struct nfp_device *nfp)
{
	kfree(nfp->hwinfo);
	nfp->hwinfo = NULL;
}

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
