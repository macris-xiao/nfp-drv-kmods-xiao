/*
 * Copyright (C) 2009-2010, Netronome Systems, Inc.  All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/time.h>

#include <linux/delay.h>

#include "i2c.h"

static inline void i2c_set_scl(struct i2c_driver *bus, int bit)
{
	bus->set_scl(bus->priv, bit);
}

static inline int i2c_get_scl(struct i2c_driver *bus)
{
	return bus->get_scl(bus->priv);
}

static inline void i2c_set_sda(struct i2c_driver *bus, int bit)
{
	bus->set_sda(bus->priv, bit);
}

static inline int i2c_get_sda(struct i2c_driver *bus)
{
	return bus->get_sda(bus->priv);
}

static inline void i2c_clock_delay(struct i2c_driver *bus)
{
	udelay(bus->delay);
}

static inline int i2c_start(struct i2c_driver *bus)
{
	int timeout = 100;

	i2c_set_scl(bus, 1);

	/* Check for clock stretched by the slave
	 */
	while ((timeout-- > 0) && (i2c_get_scl(bus) == 0))
		i2c_clock_delay(bus);

	if (timeout <= 0)
		return -EAGAIN;

	i2c_set_sda(bus, 1);
	i2c_clock_delay(bus);
	i2c_clock_delay(bus);
	i2c_clock_delay(bus);
	i2c_set_sda(bus, 0);
	i2c_clock_delay(bus);
	i2c_set_scl(bus, 0);

	return 0;
}

static inline void i2c_stop(struct i2c_driver *bus)
{
	i2c_set_scl(bus, 0);
	i2c_set_sda(bus, 0);
	i2c_clock_delay(bus);
	i2c_set_scl(bus, 1);
	i2c_clock_delay(bus);
	i2c_clock_delay(bus);
	i2c_set_sda(bus, 1);
	i2c_clock_delay(bus);
	i2c_set_sda(bus, -1);
	i2c_set_scl(bus, -1);
}

static inline void i2c_ack(struct i2c_driver *bus, int ack)
{
	i2c_set_scl(bus, 0);
	i2c_clock_delay(bus);
	i2c_set_sda(bus, ack);
	i2c_clock_delay(bus);
	i2c_set_scl(bus, 1);
	i2c_clock_delay(bus);
	i2c_clock_delay(bus);
	i2c_set_scl(bus, 0);
	i2c_clock_delay(bus);
}

static inline int i2c_writeb(struct i2c_driver *bus, uint8_t data)
{
	int i, nack;

	for (i = 0; i < 8; i++) {
		i2c_set_scl(bus, 0);
		i2c_clock_delay(bus);
		i2c_set_sda(bus, (data >> (7 - i)) & 1);
		i2c_clock_delay(bus);
		i2c_set_scl(bus, 1);
		i2c_clock_delay(bus);
		i2c_clock_delay(bus);
	}

	i2c_set_scl(bus, 0);
	i2c_set_sda(bus, -1);
	i2c_clock_delay(bus);
	i2c_clock_delay(bus);
	i2c_set_scl(bus, 1);
	i2c_clock_delay(bus);
	nack = i2c_get_sda(bus);
	i2c_set_scl(bus, 0);
	i2c_clock_delay(bus);
	i2c_set_sda(bus, -1);

	if (nack)
		return -ENODEV;

	return 0;
}

static inline uint8_t i2c_readb(struct i2c_driver *bus, int ack)
{
	uint8_t tmp;
	int i;

	tmp = 0;
	i2c_set_sda(bus, -1);
	for (i = 0; i < 8; i++) {
		i2c_set_scl(bus, 0);
		i2c_clock_delay(bus);
		i2c_clock_delay(bus);
		i2c_set_scl(bus, 1);
		i2c_clock_delay(bus);
		tmp |= i2c_get_sda(bus) << (7 - i);
		i2c_clock_delay(bus);
	}

	i2c_ack(bus, ack);

	return tmp;
}

static inline void i2c_reset(struct i2c_driver *bus)
{
	int i;

	i2c_set_scl(bus, 1);
	i2c_set_sda(bus, 1);
	i2c_set_sda(bus, -1);

	/* Clock out 9 ticks, to drain (hopefully) any I2C device */
	for (i = 0; i < 9; i++) {
		i2c_set_scl(bus, 0);
		i2c_clock_delay(bus);
		i2c_set_scl(bus, 1);
		i2c_clock_delay(bus);
	}

	i2c_stop(bus);
}

int i2c_init(struct i2c_driver *bus, unsigned clock_rate)
{
	/* Convert from freq to usec */
	bus->delay = (1000000 / clock_rate);

	i2c_reset(bus);

	return 0;
}

static int ms_timeout(struct timeval *tv_epoc, long timeout_ms)
{
	struct timeval tv;
	unsigned long ms;

	if (timeout_ms < 0) {
		do_gettimeofday(tv_epoc);
		return 0;
	}

	do_gettimeofday(&tv);

	ms = (tv.tv_usec - tv_epoc->tv_usec) / 1000;
	ms += (tv.tv_sec - tv_epoc->tv_sec) * 1000;

	return (timeout_ms < ms);
}

int i2c_cmd(struct i2c_driver *bus, uint8_t chip, const uint8_t *w_buff,
		size_t w_len, uint8_t *r_buff, size_t r_len)
{
	int i, err;
	struct timeval tv;

	ms_timeout(&tv, -1);

retry:
	err = i2c_start(bus);
	if (err < 0)
		return err;

	/* Send chip ID */
	err = i2c_writeb(bus, chip << 1);
	if (err < 0) {
		i2c_stop(bus);
		return err;
	}

	/* Send register address */
	while (w_len > 0) {
		w_len--;
		err = i2c_writeb(bus, *(w_buff++));
		if (err < 0) {
			i2c_stop(bus);
			return err;
		}
	}

	if (r_len == 0)
		goto done;

	/* Repeated Start */
	err = i2c_start(bus);
	if (err == -EAGAIN && !ms_timeout(&tv, bus->timeout_ms))
		goto retry;

	err = i2c_writeb(bus, (chip << 1) | 1);
	if (err < 0) {
		i2c_stop(bus);
		return err;
	}

	/* Get register data */
	for (i = 0; i < r_len; i++) {
		int ack = (i == (r_len - 1)) ? 1 : 0;

		r_buff[i] = i2c_readb(bus, ack);
	}

	if (i != r_len)
		err = -EIO;

done:
	i2c_stop(bus);

	return err;
}

int i2c_write(struct i2c_driver *bus, uint8_t chip, unsigned int addr,
	      size_t alen, const uint8_t *buff, size_t buff_len)
{
	int i, err;
	struct timeval tv;

	ms_timeout(&tv, -1);

	do {
		err = i2c_start(bus);
	} while (err == -EAGAIN && !ms_timeout(&tv, bus->timeout_ms));

	if (err) {
		i2c_stop(bus);
		return err;
	}

	/* Send chip ID */
	err = i2c_writeb(bus, chip << 1);
	if (err < 0) {
		i2c_stop(bus);
		return err;
	}

	/* Send register address */
	while (alen > 0) {
		alen--;
		err = i2c_writeb(bus, addr >> (alen * 8));
		if (err < 0) {
			i2c_stop(bus);
			return err;
		}
	}

	/* Get register data */
	for (i = 0; i < buff_len; i++) {
		err = i2c_writeb(bus, buff[i]);
		if (err < 0) {
			i2c_stop(bus);
			return err;
		}
	}
	i2c_stop(bus);

	return 0;
}

int i2c_read(struct i2c_driver *bus, uint8_t chip, unsigned int addr,
	     size_t alen, uint8_t *buff, size_t buff_len)
{
	int i, err;
	struct timeval tv;

	ms_timeout(&tv, -1);

retry:
	err = i2c_start(bus);
	if (err == -EAGAIN && !ms_timeout(&tv, bus->timeout_ms))
		goto retry;

	/* Send chip ID */
	err = i2c_writeb(bus, chip << 1);
	if (err < 0) {
		i2c_stop(bus);
		return err;
	}

	/* Send register address */
	while (alen > 0) {
		alen--;
		err = i2c_writeb(bus, addr >> (alen * 8));
		if (err < 0) {
			i2c_stop(bus);
			return err;
		}
	}

	/* Repeated Start */
	err = i2c_start(bus);
	if (err == -EAGAIN && !ms_timeout(&tv, bus->timeout_ms))
		goto retry;

	err = i2c_writeb(bus, (chip << 1) | 1);
	if (err < 0) {
		i2c_stop(bus);
		return err;
	}

	/* Get register data */
	for (i = 0; i < buff_len; i++) {
		int ack = (i == (buff_len - 1)) ? 1 : 0;

		buff[i] = i2c_readb(bus, ack);
	}
	i2c_stop(bus);

	return 0;
}
/* vim: set shiftwidth=8 noexpandtab: */
