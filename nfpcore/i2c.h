/*
 * Copyright (C) 2009 Netronome Systems, Inc.  All rights reserved.
 *
 */

#ifndef I2C_H
#define I2C_H

#include <linux/kernel.h>

#define I2C_BUS_MAX 8   /* Up to 8 I2C busses */

struct i2c_driver {
	void (*set_scl)(void *priv, int bit);
	int  (*get_scl)(void *priv);
	void (*set_sda)(void *priv, int bit);   /* -1 = tristate for input */
	int  (*get_sda)(void *priv);
	unsigned delay;
	long timeout_ms;
	void *priv;
};

int i2c_init(struct i2c_driver *bus, unsigned clock_rate);

int i2c_cmd(struct i2c_driver *bus, uint8_t chip,
	    const uint8_t *w_buff, size_t w_len, uint8_t *r_buff, size_t r_len);

int i2c_write(struct i2c_driver *bus, uint8_t chip, unsigned int addr,
	      size_t addr_len, const uint8_t *buffer, size_t len);

int i2c_read(struct i2c_driver *bus, uint8_t chip, unsigned int addr,
	     size_t addr_len, uint8_t *buffer, size_t len);

int i2c_write(struct i2c_driver *bus, uint8_t chip, unsigned int addr,
	      size_t addr_len, const uint8_t *buffer, size_t len);

#endif /* I2C_H */
/* vim: set shiftwidth=8 noexpandtab: */
