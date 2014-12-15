/*
 * Copyright (C) 2010-2011, Netronome Systems, Inc.  All rights reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include "nfp_device.h"
#include "nfp_cpp.h"
#include "nfp_i2c.h"
#include "nfp_gpio.h"

#include "i2c.h"
#include "i2c_gpio.h"

#define I2C_SPEED_DEFAULT       (100 * 1000) /* 100Khz */
#define I2C_TIMEOUT_DEFAULT     (100)        /* 100ms */

struct nfp_i2c {
	int initialized;
	struct i2c_driver bus;
	struct i2c_gpio_priv gpio;
};

/**
 * NFP I2C Bus creation
 */
struct nfp_i2c *nfp_i2c_alloc(struct nfp_device *nfp,
			      int gpio_scl, int gpio_sda)
{
	struct nfp_i2c *i2c;
	uint32_t model;
	int pins;

	model = nfp_cpp_model(nfp_device_cpp(nfp));

	if (NFP_CPP_MODEL_IS_3200(model))
		pins = 12;
	else if (NFP_CPP_MODEL_IS_6000(model))
		pins = 32;
	else
		return NULL;

	if (gpio_scl < 0 || gpio_scl >= pins)
		return NULL;

	if (gpio_sda < 0 || gpio_sda >= pins)
		return NULL;

	if (gpio_scl == gpio_sda)
		return NULL;

	i2c = kzalloc(sizeof(*i2c), GFP_KERNEL);

	if (i2c == NULL)
		return NULL;

	i2c->gpio.gpio_scl = gpio_scl;
	i2c->gpio.gpio_sda = gpio_sda;
	i2c->gpio.speed_hz = I2C_SPEED_DEFAULT;
	i2c->gpio.dev      = nfp;
	i2c->bus.timeout_ms = I2C_TIMEOUT_DEFAULT;

	i2c->initialized = 0;

	return i2c;
}

void nfp_i2c_free(struct nfp_i2c *i2c)
{
	kfree(i2c);
}

int nfp_i2c_set_speed(struct nfp_i2c *i2c, unsigned int speed_hz)
{
	if (speed_hz == 0)
		speed_hz = I2C_SPEED_DEFAULT;

	i2c->gpio.speed_hz = speed_hz;

	return 0;
}


int nfp_i2c_set_timeout(struct nfp_i2c *i2c, long timeout_ms)
{
	if (timeout_ms <= 0)
		timeout_ms = I2C_TIMEOUT_DEFAULT;

	i2c->bus.timeout_ms = timeout_ms;

	return 0;
}


/**
 * NFP I2C Command
 */
int nfp_i2c_cmd(struct nfp_i2c *i2c, int i2c_dev,
		const void *w_buff, size_t w_len, void *r_buff, size_t r_len)
{
	if (!i2c->initialized) {
		int err = i2c_gpio_init(&i2c->bus, &i2c->gpio);

		if (err < 0)
			return err;
		i2c->initialized = 1;
	}

	return i2c_cmd(&i2c->bus, i2c_dev, w_buff, w_len, r_buff, r_len);
}

int nfp_i2c_read(struct nfp_i2c *i2c, int i2c_dev, uint32_t address,
		 size_t a_len, void *r_buff, size_t r_len)
{
	if (!i2c->initialized) {
		int err = i2c_gpio_init(&i2c->bus, &i2c->gpio);

		if (err < 0)
			return err;
		i2c->initialized = 1;
	}

	return i2c_read(&i2c->bus, i2c_dev, address, a_len, r_buff, r_len);
}

int nfp_i2c_write(struct nfp_i2c *i2c, int i2c_dev, uint32_t address,
		  size_t a_len, const void *w_buff, size_t w_len)
{
	if (!i2c->initialized) {
		int err = i2c_gpio_init(&i2c->bus, &i2c->gpio);

		if (err < 0)
			return err;
		i2c->initialized = 1;
	}

	return i2c_write(&i2c->bus, i2c_dev, address, a_len, w_buff, w_len);
}
/* vim: set shiftwidth=8 noexpandtab: */
