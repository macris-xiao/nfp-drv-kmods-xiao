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
 * nfp_i2c_alloc() - NFP I2C Bus creation
 * @nfp:	NFP Device handle
 * @gpio_scl:	NFP GPIO pin for I2C SCL
 * @gpio_sda:	NFP GPIO pin for I2C SDA
 *
 * Return: NFP I2C handle, or NULL
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

/**
 * nfp_i2c_free() - Release a NFP I2C bus, and free its memory
 * @i2c:	NFP I2C handle
 *
 * As a side effect, the GPIO pins used for SCL and SDA will
 * be set to the 'input' direction when this call returns.
 */
void nfp_i2c_free(struct nfp_i2c *i2c)
{
	kfree(i2c);
}

/**
 * nfp_i2c_set_speed() - NFP I2C clock rate
 * @i2c:	NFP I2C handle
 * @speed_hz:	Speed in HZ. Use 0 for the default (100Khz)
 *
 * Return: 0, or -ERRNO
 */
int nfp_i2c_set_speed(struct nfp_i2c *i2c, unsigned int speed_hz)
{
	if (speed_hz == 0)
		speed_hz = I2C_SPEED_DEFAULT;

	i2c->gpio.speed_hz = speed_hz;

	return 0;
}

/**
 * nfp_i2c_set_timeout() - NFP I2C Timeout setup
 * @i2c:	NFP I2C handle
 * @timeout_ms:	Timeout in milliseconds, -1 for forever
 *
 * Return: 0, or -ERRNO
 */
int nfp_i2c_set_timeout(struct nfp_i2c *i2c, long timeout_ms)
{
	if (timeout_ms <= 0)
		timeout_ms = I2C_TIMEOUT_DEFAULT;

	i2c->bus.timeout_ms = timeout_ms;

	return 0;
}


/**
 * nfp_i2c_cmd() - NFP I2C Command
 * @i2c:	I2C Bus
 * @i2c_dev:	I2C Device ( 7-bit address )
 * @w_buff:	Data to write to device
 * @w_len:	Length in bytes to write (must be >= 1)
 * @r_buff:	Data to read from device (can be NULL if r_len == 0)
 * @r_len:	Length in bytes to read (must be >= 0)
 *
 * Return: 0, or -ERRNO
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

/**
 * nfp_i2c_read() - NFP I2C Read
 * @i2c:	I2C Bus
 * @i2c_dev:	I2C Device ( 7-bit address )
 * @addr:	Device address
 * @a_len:	Length (in bytes) of the device address
 * @r_buff:	Data to read from device (can be NULL if r_len == 0)
 * @r_len:	Length in bytes to read (must be >= 0)
 *
 * Return: 0, or -ERRNO
 */
int nfp_i2c_read(struct nfp_i2c *i2c, int i2c_dev, uint32_t addr,
		 size_t a_len, void *r_buff, size_t r_len)
{
	if (!i2c->initialized) {
		int err = i2c_gpio_init(&i2c->bus, &i2c->gpio);

		if (err < 0)
			return err;
		i2c->initialized = 1;
	}

	return i2c_read(&i2c->bus, i2c_dev, addr, a_len, r_buff, r_len);
}

/**
 * nfp_i2c_read() - NFP I2C Write
 * @i2c:	I2C Bus
 * @i2c_dev:	I2C Device ( 7-bit address )
 * @addr:	Device address
 * @a_len:	Length (in bytes) of the device address
 * @w_buff:	Data to write to device
 * @w_len:	Length in bytes to write (must be >= 1)
 *
 * Return: 0, or -ERRNO
 */
int nfp_i2c_write(struct nfp_i2c *i2c, int i2c_dev, uint32_t addr,
		  size_t a_len, const void *w_buff, size_t w_len)
{
	if (!i2c->initialized) {
		int err = i2c_gpio_init(&i2c->bus, &i2c->gpio);

		if (err < 0)
			return err;
		i2c->initialized = 1;
	}

	return i2c_write(&i2c->bus, i2c_dev, addr, a_len, w_buff, w_len);
}
