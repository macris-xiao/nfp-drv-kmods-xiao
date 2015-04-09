/*
 * Copyright (C) 2014-2015, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_I2C_H
#define NFP_I2C_H

struct nfp_i2c;

struct nfp_i2c *nfp_i2c_alloc(struct nfp_device *dev,
		  int gpio_scl, int gpio_sda);
void nfp_i2c_free(struct nfp_i2c *bus);

int nfp_i2c_set_speed(struct nfp_i2c *bus, unsigned int speed_hz);
int nfp_i2c_set_timeout(struct nfp_i2c *bus, long timeout_ms);

int nfp_i2c_cmd(struct nfp_i2c *bus, int i2c_dev,
		const void *w_buff, size_t w_len,
		void *r_buff, size_t r_len);
int nfp_i2c_read(struct nfp_i2c *bus, int i2c_dev,
		 uint32_t addr, size_t a_len,
		 void *r_buff, size_t r_len);
int nfp_i2c_write(struct nfp_i2c *bus, int i2c_dev,
		  uint32_t address, size_t a_len,
		  const void *w_buff, size_t w_len);

#endif /* NFP_I2C_H */
