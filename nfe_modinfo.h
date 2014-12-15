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
 * vim:shiftwidth=8:noexpandtab
 *
 * @file kernel/nfe_modinfo.h
 *
 * Common declarations for defining module build information.
 */
#ifndef __KERNEL__NFE_MODINFO_H__
#define __KERNEL__NFE_MODINFO_H__

#include "nfe_build_info.h"	/* dynamically generated filed */

#define MODULE_INFO_NFP() \
	MODULE_INFO(nfp_src_version, NFP_SRC_VERSION); \
	MODULE_INFO(nfp_src_path, NFP_SRC_PATH); \
	MODULE_INFO(nfp_build_user_id, NFP_BUILD_USER_ID); \
	MODULE_INFO(nfp_build_user, NFP_BUILD_USER); \
	MODULE_INFO(nfp_build_host, NFP_BUILD_HOST); \
	MODULE_INFO(nfp_build_path, NFP_BUILD_PATH);

#define NFP_BUILD_DESCRIPTION(drvname)				\
	#drvname " src version: " NFP_SRC_VERSION "\n"		\
	#drvname " src path: " NFP_SRC_PATH "\n"		\
	#drvname " build user id: " NFP_BUILD_USER_ID "\n"	\
	#drvname " build user: " NFP_BUILD_USER "\n"		\
	#drvname " build host: " NFP_BUILD_HOST "\n"		\
	#drvname " build path: " NFP_BUILD_PATH "\n"

#endif	/* __KERNEL__NFE_MODINFO_H__ */
