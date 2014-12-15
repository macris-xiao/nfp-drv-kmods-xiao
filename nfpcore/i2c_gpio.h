/*
 * Copyright (C) 2009 Netronome Systems, Inc.  All rights reserved.
 *
 */

#ifndef I2C_GPIO_H
#define I2C_GPIO_H

#include "nfp_device.h"

#include "i2c.h"

struct i2c_gpio_priv {
	unsigned int gpio_scl;
	unsigned int gpio_sda;
	unsigned int speed_hz;
	struct nfp_device *dev;
};

int i2c_gpio_init(struct i2c_driver *drv, struct i2c_gpio_priv *priv);

#endif /* I2C_GPIO_H */
/* vim: set shiftwidth=8 noexpandtab: */
