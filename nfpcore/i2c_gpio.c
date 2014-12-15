/*
 * Copyright (C) 2009-2010, Netronome Systems, Inc.  All rights reserved.
 *
 */
#include <linux/kernel.h>

#include "nfp_gpio.h"

#include "i2c.h"
#include "i2c_gpio.h"

static void i2c_gpio_set_scl(void *priv, int bit)
{
	struct i2c_gpio_priv *i2c = priv;

	if (bit < 0) { /* Tristate */
		nfp_gpio_direction(i2c->dev, i2c->gpio_scl, 0);
	} else {
		nfp_gpio_set(i2c->dev, i2c->gpio_scl, bit);
		nfp_gpio_direction(i2c->dev, i2c->gpio_scl, 1);
	}
}

static int i2c_gpio_get_scl(void *priv)
{
	struct i2c_gpio_priv *i2c = priv;
	int val;

	/* On the NFP, detection of SCL clock
	 * stretching by slave is not possible
	 * on Bus 0, since GPIO0 may have a
	 * pull-up/pull-down to force the ARM/PCIE
	 * boot selection. In this case, always
	 * return 1, so that the SCL clock
	 * stretching logic is not used.
	 */
	if (i2c->gpio_scl == 0)
		return 1;

	nfp_gpio_direction(i2c->dev, i2c->gpio_scl, 0);
	val = nfp_gpio_get(i2c->dev, i2c->gpio_scl);
	nfp_gpio_direction(i2c->dev, i2c->gpio_scl, 1);

	return val;
}

static void i2c_gpio_set_sda(void *priv, int bit)
{
	struct i2c_gpio_priv *i2c = priv;

	if (bit < 0) { /* Tristate */
		nfp_gpio_direction(i2c->dev, i2c->gpio_sda, 0);
	} else {
		nfp_gpio_set(i2c->dev, i2c->gpio_sda, bit);
		nfp_gpio_direction(i2c->dev, i2c->gpio_sda, 1);
	}
}

static int i2c_gpio_get_sda(void *priv)
{
	struct i2c_gpio_priv *i2c = priv;

	return nfp_gpio_get(i2c->dev, i2c->gpio_sda);
}

int i2c_gpio_init(struct i2c_driver *drv, struct i2c_gpio_priv *priv)
{
	int err;

	drv->set_scl = i2c_gpio_set_scl;
	drv->get_scl = i2c_gpio_get_scl;
	drv->set_sda = i2c_gpio_set_sda;
	drv->get_sda = i2c_gpio_get_sda;
	drv->priv = priv;

	i2c_gpio_set_sda(priv, -1);
	i2c_gpio_set_scl(priv, -1);

	err = i2c_init(drv, priv->speed_hz);
	if (err < 0)
		drv->priv = NULL;

	return err;
}
/* vim: set shiftwidth=8 noexpandtab: */
