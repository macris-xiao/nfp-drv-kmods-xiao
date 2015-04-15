/*
 * Copyright (C) 2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "nfp.h"
#include "nfp_cpp.h"

#define ARMSP_RESOURCE		"arm.sp"

/* Offsets relative to the CSR base */
#define ARMSP_STATUS            0x00
#define   ARMSP_STATUS_MAGIC_of(x)      (((x) >> 48) & 0xffff)
#define   ARMSP_STATUS_MAGIC(x)         (((x) & 0xffffULL) << 48)
#define   ARMSP_STATUS_MAJOR_of(x)      (((x) >> 40) & 0xf)
#define   ARMSP_STATUS_MAJOR(x)         (((x) & 0xfULL) << 40)
#define   ARMSP_STATUS_MINOR_of(x)      (((x) >> 32) & 0xfff)
#define   ARMSP_STATUS_MINOR(x)         (((x) & 0xfffULL) << 32)
#define   ARMSP_STATUS_CODE_of(x)       (((x) >> 16) & 0xffff)
#define   ARMSP_STATUS_CODE(x)          (((x) & 0xffffULL) << 16)
#define   ARMSP_STATUS_RESULT_of(x)     (((x) >>  8) & 0xff)
#define   ARMSP_STATUS_RESULT(x)        (((x) & 0xffULL) << 8)
#define   ARMSP_STATUS_BUSY             BIT_ULL(0)

#define ARMSP_COMMAND           0x08
#define   ARMSP_COMMAND_CODE(x)         (((x) & 0xffff) << 16)
#define   ARMSP_COMMAND_CODE_of(x)      (((x) >> 16) & 0xffff)
#define   ARMSP_COMMAND_START           BIT_ULL(0)

#define ARMSP_MAGIC             0xab10
#define ARMSP_MAJOR             0

#define ARMSP_CODE_MAJOR_of(code)	(((code) >> 12) & 0xf)
#define ARMSP_CODE_MINOR_of(code)	(((code) >>  0) & 0xfff)

struct nfp_armsp {
	struct nfp_resource *res;
};

static void nfp_armsp_des(void *ptr)
{
	struct nfp_armsp *priv = ptr;

	nfp_resource_release(priv->res);
}

static void *nfp_armsp_con(struct nfp_device *nfp)
{
	struct nfp_resource *res;
	struct nfp_armsp *priv;

	res = nfp_resource_acquire(nfp, ARMSP_RESOURCE);
	if (!res)
		return NULL;

	priv = nfp_device_private_alloc(nfp, sizeof(*priv), nfp_armsp_des);
	if (!priv) {
		nfp_resource_release(res);
		return priv;
	}

	priv->res = res;

	return priv;
}

/**
 * nfp_armsp_command() - Execute a command on the ARM Service Processor
 * @nfp:	NFP Device handle
 * @code:	ARM SP Command Code
 *
 * Return: 0 for success with no result
 *
 *         1..255 for ARM SP completion with a result code
 *
 *         -EAGAIN if the ARM SP is not yet present
 *
 *         -ENODEV if the ARM SP is not a supported model
 *
 *         -EBUSY if the ARM SP is stuck
 *
 *         -EINTR if interrupted while waiting for completion
 *
 *         -ETIMEDOUT if the ARM SP took longer than 30 seconds to complete
 */
int nfp_armsp_command(struct nfp_device *nfp, uint16_t code)
{
	struct nfp_cpp *cpp = nfp_device_cpp(nfp);
	struct nfp_armsp *armsp;
	uint32_t arm;
	uint64_t arm_base;
	uint64_t arm_status;
	uint64_t arm_command;
	int err, ok;
	uint64_t tmp;
	int timeout = 30 * 10;	/* 30 seconds total */

	armsp = nfp_device_private(nfp, nfp_armsp_con);
	if (!armsp)
		return -EAGAIN;

	arm = nfp_resource_cpp_id(armsp->res);
	arm_base = nfp_resource_address(armsp->res);
	arm_status = arm_base + ARMSP_STATUS;
	arm_command = arm_base + ARMSP_COMMAND;

	err = nfp_cpp_readq(cpp, arm, arm_status, &tmp);
	if (err < 0)
		return err;

	if (ARMSP_MAGIC != ARMSP_STATUS_MAGIC_of(tmp)) {
		nfp_err(nfp, "ARM SP: Cannot detect ARM Service Processor\n");
		return -ENODEV;
	}

	ok = ARMSP_STATUS_MAJOR_of(tmp) == ARMSP_CODE_MAJOR_of(code) &&
	     ARMSP_STATUS_MINOR_of(tmp) >= ARMSP_CODE_MINOR_of(code);
	if (!ok) {
		nfp_err(nfp, "ARM SP: Code 0x%04x not supported (ABI %d.%d)\n",
			code,
			(int)ARMSP_STATUS_MAJOR_of(tmp),
			(int)ARMSP_STATUS_MINOR_of(tmp));
		return -EINVAL;
	}

	if (tmp & ARMSP_STATUS_BUSY) {
		nfp_err(nfp, "ARM SP: Service processor busy!\n");
		return -EBUSY;
	}

	err = nfp_cpp_writeq(cpp, arm, arm_command,
			     ARMSP_COMMAND_CODE(code) | ARMSP_COMMAND_START);
	if (err < 0)
		return err;

	/* Wait for ARMSP_COMMAND_START to go to 0 */
	for (; timeout > 0; timeout--) {
		err = nfp_cpp_readq(cpp, arm, arm_command, &tmp);
		if (err < 0)
			return err;

		if (!(tmp & ARMSP_COMMAND_START))
			break;

		if (msleep_interruptible(100) > 0) {
			nfp_warn(nfp, "ARM SP: Interrupt waiting for code 0x%04x to start\n",
				 code);
			return -EINTR;
		}
	}

	if (timeout < 0) {
		nfp_warn(nfp, "ARM SP: Timeout waiting for code 0x%04x to start\n",
			 code);
		return -ETIMEDOUT;
	}

	/* Wait for ARMSP_STATUS_BUSY to go to 0 */
	for (; timeout > 0; timeout--) {
		err = nfp_cpp_readq(cpp, arm, arm_status, &tmp);
		if (err < 0)
			return err;

		if (!(tmp & ARMSP_STATUS_BUSY))
			break;

		if (msleep_interruptible(100) > 0) {
			nfp_warn(nfp, "ARM SP: Interrupt waiting for code 0x%04x to complete\n",
				 code);
			return -EINTR;
		}
	}

	if (timeout < 0) {
		nfp_warn(nfp, "ARM SP: Timeout waiting for code 0x%04x to complete\n",
			 code);
		return -ETIMEDOUT;
	}

	return (int)ARMSP_STATUS_RESULT_of(tmp);
}
