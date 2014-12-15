/*
 * Copyright (C) 2009-2010, Netronome Systems, Inc.  All rights reserved.
 *
 */

#include <linux/kernel.h>

#include "nfp_device.h"
#include "nfp_gpio.h"
#include "nfp_cpp.h"

#include "nfp3200/nfp3200.h"
#include "nfp3200/nfp_xpb.h"
#include "nfp3200/nfp_gpio.h"

#include "nfp6000/nfp6000.h"

#define NFP_ARM_GPIO                                         (0x403000)


struct gpio {
	int pins;
	int (*readl)(struct nfp_cpp *cpp, int csr_offset, uint32_t *val);
	int (*writel)(struct nfp_cpp *cpp, int csr_offset, uint32_t val);
};

static int nfp3200_csr_readl(struct nfp_cpp *cpp, int csr_offset, uint32_t *val)
{
	return nfp_xpb_readl(cpp, NFP_XPB_GPIO + csr_offset, val);
}

static int nfp3200_csr_writel(struct nfp_cpp *cpp, int csr_offset, uint32_t val)
{
	return nfp_xpb_writel(cpp, NFP_XPB_GPIO + csr_offset, val);
}

#define NFP_ARM_ID  NFP_CPP_ID(NFP_CPP_TARGET_ARM, NFP_CPP_ACTION_RW, 0)

static int nfp6000_csr_readl(struct nfp_cpp *cpp, int csr_offset, uint32_t *val)
{
	return nfp_cpp_readl(cpp, NFP_ARM_ID, NFP_ARM_GPIO + csr_offset, val);
}

static int nfp6000_csr_writel(struct nfp_cpp *cpp, int csr_offset, uint32_t val)
{
	return nfp_cpp_writel(cpp, NFP_ARM_ID, NFP_ARM_GPIO + csr_offset, val);
}

static void *gpio_new(struct nfp_device *nfp)
{
	uint32_t model;
	struct gpio *gpio;

	gpio = nfp_device_private_alloc(nfp, sizeof(*gpio), NULL);
	if (gpio == NULL)
		return NULL;

	model = nfp_cpp_model(nfp_device_cpp(nfp));

	if (NFP_CPP_MODEL_IS_3200(model)) {
		gpio->pins = 12;
		gpio->readl = nfp3200_csr_readl;
		gpio->writel = nfp3200_csr_writel;
	} else if (NFP_CPP_MODEL_IS_6000(model)) {
		gpio->pins = 32;
		gpio->readl = nfp6000_csr_readl;
		gpio->writel = nfp6000_csr_writel;
	} else {
		gpio->pins = 0;
		gpio->readl = NULL;
		gpio->writel = NULL;
	}

	return gpio;
}

int nfp_gpio_pins(struct nfp_device *dev)
{
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t model;
	int max_pin;

	if (cpp == NULL)
		return -ENODEV;

	model = nfp_cpp_model(cpp);
	if (NFP_CPP_MODEL_IS_3200(model))
		max_pin = 12;
	else if (NFP_CPP_MODEL_IS_6000(model))
		max_pin = 32;
	else
		max_pin = 0;

	return max_pin;
}


/**
 * GPIO Pin Setup
 *
 * @param dev       NFP device
 * @param gpio_pin  GPIO Pin (0 .. 11)
 * @param is_output 0 = input, 1 = output
 * @return      Error code
 */
int nfp_gpio_direction(struct nfp_device *dev, int gpio_pin, int is_output)
{
	struct gpio *gpio = nfp_device_private(dev, gpio_new);
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t mask;
	int err;

	if (gpio_pin < 0 || gpio_pin >= gpio->pins)
		return -EINVAL;

	mask = (1 << gpio_pin);

	if (is_output)
		err = gpio->writel(cpp, NFP_GPIO_PDSR, mask);
	else
		err = gpio->writel(cpp, NFP_GPIO_PDCR, mask);

	return err < 0 ? err : 0;
}


/**
 * GPIO Get Pin Direction
 *
 * @param dev       NFP device
 * @param gpio_pin  GPIO Pin (0 .. X)
 * @param is_output 0 = input, 1 = output
 * @return      Error code
 */
int nfp_gpio_get_direction(struct nfp_device *dev, int gpio_pin, int *is_output)
{
	struct gpio *gpio = nfp_device_private(dev, gpio_new);
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t val;
	int err;

	if (gpio_pin < 0 || gpio_pin >= gpio->pins)
		return -EINVAL;

	err = gpio->readl(cpp, NFP_GPIO_PDPR, &val);

	if (err >= 0)
		*is_output = (val >> gpio_pin) & 1;

	return err;
}

/**
 * GPIO Pin Input
 *
 * @param dev       NFP device
 * @param gpio_pin  GPIO Pin (0 .. 11)
 * @return      0, 1 = value of pin, < 0 = error code
 */
int nfp_gpio_get(struct nfp_device *dev, int gpio_pin)
{
	struct gpio *gpio = nfp_device_private(dev, gpio_new);
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t mask, value;
	int err;

	if (gpio_pin < 0 || gpio_pin >= gpio->pins)
		return -EINVAL;

	err = gpio->readl(cpp, NFP_GPIO_PLR, &value);
	if (err < 0)
		return err;

	mask = (1 << gpio_pin);

	return (value & mask) ? 1 : 0;
}

/**
 * GPIO Pin Output
 *
 * @param dev       NFP device
 * @param gpio_pin  GPIO Pin (0 .. 11)
 * @param value     0, 1
 * @return      0 = success, < 0 = error code
 */
int nfp_gpio_set(struct nfp_device *dev, int gpio_pin, int value)
{
	struct gpio *gpio = nfp_device_private(dev, gpio_new);
	struct nfp_cpp *cpp = nfp_device_cpp(dev);
	uint32_t mask;
	int err;

	if (gpio_pin < 0 || gpio_pin >= gpio->pins)
		return -EINVAL;

	mask = (1 << gpio_pin);

	if (value == 0)
		err = gpio->writel(cpp, NFP_GPIO_POCR, mask);
	else
		err = gpio->writel(cpp, NFP_GPIO_POSR, mask);

	return err < 0 ? err : 0;
}
/* vim: set shiftwidth=8 noexpandtab: */
