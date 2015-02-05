/**
 * Copyright (C) 2013-2015 Netronome Systems, Inc.  All rights reserved.
 *
 * @file nfp_phymod.c
 */

#include <linux/kernel.h>

#include "nfp.h"
#include "nfp_resource.h"
#include "nfp_hwinfo.h"
#include "nfp_gpio.h"
#include "nfp_i2c.h"
#include "nfp_nbi_phymod.h"

struct nfp_phymod;
struct nfp_phymod_eth;

struct sff_ops {
	int type;
	int (*open)(struct nfp_phymod *phy);
	void (*close)(struct nfp_phymod *phy);

	int (*poll_present)(struct nfp_phymod *phy);
	int (*poll_irq)(struct nfp_phymod *phy);

	int (*select)(struct nfp_phymod *phy, int is_selected);
	int (*reset)(struct nfp_phymod *phy, int in_reset);
	int (*power)(struct nfp_phymod *phy, int is_full_power);

	int (*read8)(struct nfp_phymod *phy, uint32_t reg, uint8_t *val);
	int (*write8)(struct nfp_phymod *phy, uint32_t reg, uint8_t val);

	int (*status_los)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*status_fault)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*status_power)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*status_bias)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*status_volt)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*status_temp)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);

	int (*get_lane_dis)(struct nfp_phymod *phy, uint32_t *tx, uint32_t *rx);
	int (*set_lane_dis)(struct nfp_phymod *phy, uint32_t tx, uint32_t rx);
};

struct nfp_key {
	struct nfp_device *nfp;
	char key[16];
};

struct nfp_phymod_priv {
	struct nfp_device *nfp;
	int selected;
	int phymods;
	struct nfp_phymod {
		struct nfp_phymod_priv *priv;
		int index;
		char key[16];
		char *label;
		int nbi;
		int type;
		int port, lanes;
		struct {
			const struct sff_ops *op;
			void *priv;
		} sff;
	} phymod[48];
	int eths;
	struct nfp_phymod_eth {
		struct nfp_phymod_priv *priv;
		int index;
		char key[16];
		char *label;
		uint8_t mac[6];
		int lane;
		int lanes;
		struct nfp_phymod *phymod;
        } eth[48];
};

static void _phymod_private_free(void *_priv)
{
	struct nfp_phymod_priv *priv = _priv;
	int n;

	for (n = 0; n < priv->phymods; n++) {
		struct nfp_phymod *phy = &priv->phymod[n];
		if (phy->sff.op && phy->sff.op->close)
			phy->sff.op->close(phy);
		if (phy->label)
			kfree(phy->label);
	}
	for (n = 0; n < priv->eths; n++) {
		struct nfp_phymod_eth *eth = &priv->eth[n];
		if (eth->label)
			kfree(eth->label);
	}
}

static const struct {
	const char *name;
	int type;
} typemap[] = {
	{ "SFP", NFP_PHYMOD_TYPE_SFP },
	{ "SFP+", NFP_PHYMOD_TYPE_SFPP },
	{ "QSFP", NFP_PHYMOD_TYPE_QSFP },
	{ "CXP", NFP_PHYMOD_TYPE_CXP },
};

static const char *_phymod_get_attr(struct nfp_phymod *phy, const char *attr)
{
	char buff[32];
	snprintf(buff, sizeof(buff), "%s.%s", phy->key, attr);
	buff[sizeof(buff)-1] = 0;

	return nfp_hwinfo_lookup(phy->priv->nfp, buff);
}

static int _phymod_get_attr_int(struct nfp_phymod *phy,
				const char *attr, int *val)
{
	const char *ptr;

	ptr = _phymod_get_attr(phy, attr);
	if (!ptr)
		return -EINVAL;

	return kstrtoint(ptr, 0, val);
}

static const char *_eth_get_attr(struct nfp_phymod_eth *eth, const char *attr)
{
	char buff[32];
	snprintf(buff, sizeof(buff), "%s.%s", eth->key, attr);
	buff[sizeof(buff)-1] = 0;

	return nfp_hwinfo_lookup(eth->priv->nfp, buff);
}

static int _eth_get_attr_int(struct nfp_phymod_eth *eth, const char *attr, int *val)
{
	const char *ptr;

	ptr = _eth_get_attr(eth, attr);
	if (!ptr)
		return -EINVAL;

	return kstrtoint(ptr, 0, val);
}

static int _eth_get_attr_mac(struct nfp_phymod_eth *eth, const char *attr, uint8_t *mac)
{
	const char *ptr;

	ptr = _eth_get_attr(eth, attr);
	if (ptr) {
		int err;

		err = sscanf(ptr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);
		if (err != 6)
			return -EINVAL;
	} else {
		memset(mac, 0, 6);
	}

	return 0;
}

static int _phymod_lookup_type(const char *cp)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(typemap); i++) {
		if (strcmp(cp, typemap[i].name) == 0)
			return typemap[i].type;
	}

	return NFP_PHYMOD_TYPE_NONE;
}

struct sff_bus;

struct sff_bus_ops {
	const char *prefix;
	int (*open)(struct sff_bus *bus, const char *storage);
	void (*close)(struct sff_bus *bus);
	int (*select)(struct sff_bus *bus, int is_selected);
	int (*read8)(struct sff_bus *bus, uint32_t reg, uint8_t *val);
	int (*write8)(struct sff_bus *bus, uint32_t reg, uint8_t val);
};

struct sff_bus {
	struct nfp_device *nfp;
	const struct sff_bus_ops *op;
	void *priv;
};

/* I2C direct-sttach */
struct bus_i2c {
	struct nfp_i2c *i2c;
	int scl, sda;
	uint8_t addr;
};

static int bus_i2c_open(struct sff_bus *bus, const char *storage)
{
	struct bus_i2c *priv;
	int i2c_bus, i2c_addr, i2c_offset;
	int rc;

	/* ee1:4:0x50:0 */
	rc = sscanf(storage, "ee1:%i:%i:%i", &i2c_bus, &i2c_addr, &i2c_offset);
	if (rc != 3)
		return -EINVAL;

	(void)i2c_offset; /* Ignored */

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->scl = i2c_bus * 2;
	priv->sda = i2c_bus * 2 + 1;
	priv->addr = i2c_addr;
	bus->priv = priv;

	return 0;
}

static void bus_i2c_close(struct sff_bus *bus)
{
	struct bus_i2c *priv = bus->priv;

	bus->op->select(bus, 0);
	kfree(priv);
}

static int bus_i2c_select(struct sff_bus *bus, int is_selected)
{
	struct bus_i2c *priv = bus->priv;

	if (is_selected) {
		if (!priv->i2c) {
			priv->i2c = nfp_i2c_alloc(bus->nfp,
						  priv->scl, priv->sda);
			if (priv->i2c == NULL)
				return -EINVAL;
			/* Set to default rate */
			nfp_i2c_set_speed(priv->i2c, 0);
		}
	} else {
		if (priv->i2c)
			nfp_i2c_free(priv->i2c);
		priv->i2c = NULL;
	}

	return 0;
}

static int bus_i2c_read8(struct sff_bus *bus, uint32_t reg, uint8_t *val)
{

	struct bus_i2c *priv = bus->priv;

	if (!priv->i2c)
		return -EINVAL;

	return nfp_i2c_read(priv->i2c, priv->addr, reg, 1, val, 1);
}

static int bus_i2c_write8(struct sff_bus *bus, uint32_t reg, uint8_t val)
{
	struct bus_i2c *priv = bus->priv;

	if (!priv->i2c)
		return -EINVAL;

	return nfp_i2c_write(priv->i2c, priv->addr, reg, 1, &val, 1);
}

static const struct sff_bus_ops sff_bus_i2c = {
	.prefix = "ee1:",
	.open = bus_i2c_open,
	.close = bus_i2c_close,
	.select = bus_i2c_select,
	.read8 = bus_i2c_read8,
	.write8 = bus_i2c_write8,
};

static const struct sff_bus_ops *sff_bus_op_table[] = {
	&sff_bus_i2c,
};

static int _phymod_get_attr_bus(struct nfp_phymod *phy, const char *attr,
				struct sff_bus *bus)
{
	const char *cp;
	int i;

	bus->nfp = phy->priv->nfp;

	cp = _phymod_get_attr(phy, attr);
	if (!cp)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(sff_bus_op_table); i++) {
		if (strncmp(cp, sff_bus_op_table[i]->prefix,
			    strlen(sff_bus_op_table[i]->prefix)) == 0) {
			int err;

			bus->op = sff_bus_op_table[i];

			if (bus->op->open)
				err = bus->op->open(bus, cp);
			else
				err = 0;

			if (err < 0)
				bus->op = NULL;

			return err;
		}
	}

	return -ENOENT;
}

/* SFF-8436 operations */
struct sff_8436 {
	int selected;
	int page;
	struct {
		int irq, present;
	} in;
	struct {
		int modsel, reset, lp_mode;
	} out;
	struct sff_bus bus;
};

static int sff_8436_open(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff;
	int err;

	sff = kzalloc(sizeof(*sff), GFP_KERNEL);
	if (!sff)
		return -ENOMEM;

	sff->selected = 0;
	sff->page = -1;

	err = _phymod_get_attr_int(phy, "gpio.irq", &sff->in.irq);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_int(phy, "gpio.present", &sff->in.present);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_int(phy, "gpio.modsel", &sff->out.modsel);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_int(phy, "gpio.reset", &sff->out.reset);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_int(phy, "gpio.lp_mode", &sff->out.lp_mode);
	if (err < 0)
		goto exit;

	err = nfp_gpio_direction(priv->nfp, sff->in.irq, 0);
	if (err < 0)
		goto exit;

	err = nfp_gpio_direction(priv->nfp, sff->in.present, 0);
	if (err < 0)
		goto exit;

	err = nfp_gpio_direction(priv->nfp, sff->out.modsel, 1);
	if (err < 0)
		goto exit;

	err = nfp_gpio_direction(priv->nfp, sff->out.reset, 1);
	if (err < 0)
		goto exit;

	err = nfp_gpio_direction(priv->nfp, sff->out.lp_mode, 1);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_bus(phy, "SFF-8436", &sff->bus);
	if (err < 0)
		goto exit;

	phy->sff.priv = sff;

	return 0;

exit:
	kfree(sff);
	return err;
}

static void sff_8436_close(struct nfp_phymod *phy)
{
	struct sff_8436 *sff = phy->sff.priv;

	phy->sff.op->select(phy, 0);

	if (sff->bus.op && sff->bus.op->close)
		sff->bus.op->close(&sff->bus);

	kfree(sff);
}

static int sff_8436_poll_irq(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff = phy->sff.priv;
	int err;
	
	err = nfp_gpio_get(priv->nfp, sff->in.irq);
	if (err < 0)
		return err;

	return err ? 0 : 1;
}

static int sff_8436_poll_present(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff = phy->sff.priv;
	int err;

	err = nfp_gpio_get(priv->nfp, sff->in.present);
	if (err < 0)
		return err;

	return err ? 0 : 1;
}

static int sff_8436_select(struct nfp_phymod *phy, int is_selected)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff = phy->sff.priv;
	int err;

	if (sff->bus.op && sff->bus.op->select) {
		err = sff->bus.op->select(&sff->bus, is_selected);
		if (err < 0)
			return err;
	}

	err = nfp_gpio_set(priv->nfp, sff->out.modsel, is_selected ? 0 : 1);
	if (err < 0)
		return err;

	sff->selected = is_selected;

	return 0;
}

static int sff_8436_reset(struct nfp_phymod *phy, int in_reset)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff = phy->sff.priv;
	return nfp_gpio_set(priv->nfp, sff->out.reset, in_reset ? 1 : 0);
}

static int sff_8436_power(struct nfp_phymod *phy, int is_full_power)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8436 *sff = phy->sff.priv;
	return nfp_gpio_set(priv->nfp, sff->out.lp_mode, is_full_power ? 0 : 1);
}

static int sff_8436_read8(struct nfp_phymod *phy, uint32_t reg, uint8_t *val)
{
	struct sff_8436 *sff = phy->sff.priv;
	int page = (reg >> 8);

	if (!sff->selected
	    || !sff->bus.op
	    || !sff->bus.op->read8
	    || !sff->bus.op->write8)
		return -EINVAL;

	reg &= 0xff;

	if (page != sff->page) {
		sff->bus.op->write8(&sff->bus, reg, page);
		sff->page = page;
	}

	return sff->bus.op->read8(&sff->bus, reg, val);
}

static int sff_8436_write8(struct nfp_phymod *phy, uint32_t reg, uint8_t val)
{
	struct sff_8436 *sff = phy->sff.priv;
	int page = (reg >> 8);

	if (!sff->selected
	    || !sff->bus.op
	    || !sff->bus.op->write8)
		return -EINVAL;

	reg &= 0xff;

	if (page != sff->page) {
		sff->bus.op->write8(&sff->bus, reg, page);
		sff->page = page;
	}

	return sff->bus.op->write8(&sff->bus, reg, val);
}

#define SFF_8436_ID		0
#define SFF_8436_STATUS		2
#define SFF_8436_LOS		3
#define SFF_8436_FAULT_TX	4
#define SFF_8436_TEMP		6
#define SFF_8436_VCC		7
#define SFF_8436_POWER_RX_12	9
#define SFF_8436_POWER_RX_34	10
#define SFF_8436_BIAS_TX_12	11
#define SFF_8436_BIAS_TX_34	12
#define SFF_8436_DISABLE_TX	86

static int sff_8436_status_los(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_LOS, &tmp);
	if (err < 0)
		return err;

	/* Check RX LOS status bits */
	if (tmp & 0x0f)
		rxs |= tmp & 0xf;
	/* Check TX LOS status bits */
	if (tmp & 0xf0)
		txs |= (tmp >> 4) & 0xf;

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}

static int sff_8436_status_fault(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_FAULT_TX, &tmp);
	if (err < 0)
		return err;

	if (tmp & 0xf)
		txs |= tmp & 0xf;

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}

static int sff_8436_status_power(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_POWER_RX_12, &tmp);
	if (err < 0)
		return err;

	if (tmp)
		rxs |= tmp;

	err = nfp_phymod_read8(phy, SFF_8436_POWER_RX_34, &tmp);
	if (err < 0)
		return err;

	if (tmp)
		rxs |= (uint32_t)tmp << 8;


	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}
static int sff_8436_status_bias(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_BIAS_TX_12, &tmp);
	if (err < 0)
		return err;

	if (tmp)
		txs |= tmp;

	err = nfp_phymod_read8(phy, SFF_8436_BIAS_TX_34, &tmp);
	if (err < 0)
		return err;

	if (tmp)
		txs |= (uint32_t)tmp << 8;

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}
static int sff_8436_status_volt(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_VCC, &tmp);
	if (err < 0)
		return err;

	if (tmp & 0xf0) {
		txs |= (tmp >> 4) & 0xf;
		rxs |= (tmp >> 4) & 0xf;
	}

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}
static int sff_8436_status_temp(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_TEMP, &tmp);
	if (err < 0)
		return err;

	if (tmp & 0xf0) {
		txs |= (tmp >> 4) & 0xf;
		rxs |= (tmp >> 4) & 0xf;
	}

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}

static int sff_8436_get_lane_dis(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	uint8_t tmp;
	int err;
	uint32_t rxs = 0, txs = 0;

	err = nfp_phymod_read8(phy, SFF_8436_DISABLE_TX, &tmp);
	if (err < 0)
		return err;

	txs = (tmp & 0x0f);

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}

static int sff_8436_set_lane_dis(struct nfp_phymod *phy,
				 uint32_t tx_status, uint32_t rx_status)
{
	return nfp_phymod_write8(phy, SFF_8436_DISABLE_TX, tx_status & 0xf);
}

static const struct sff_ops sff_8436_ops = {
	.type = 8436,
	.open = sff_8436_open,
	.close = sff_8436_close,
	.poll_present = sff_8436_poll_present,
	.poll_irq = sff_8436_poll_irq,
	.select = sff_8436_select,
	.reset = sff_8436_reset,
	.power = sff_8436_power,

	.read8 = sff_8436_read8,
	.write8 = sff_8436_write8,

	.status_los = sff_8436_status_los,
	.status_fault = sff_8436_status_fault,
	.status_power = sff_8436_status_power,
	.status_bias = sff_8436_status_bias,
	.status_volt = sff_8436_status_volt,
	.status_temp = sff_8436_status_temp,

	.get_lane_dis = sff_8436_get_lane_dis,
	.set_lane_dis = sff_8436_set_lane_dis,
};

static const struct sff_ops *sff_op_table[]  = {
	&sff_8436_ops,
};

static void *_phymod_private(struct nfp_device *nfp)
{
	struct nfp_phymod_priv *priv;
	int n;

	priv = nfp_device_private_alloc(nfp, sizeof(*priv),
					_phymod_private_free);
	if (!priv)
		return NULL;

	priv->nfp = nfp;
	priv->selected = -1;
	priv->phymods = 0;
	for (n = 0; n < ARRAY_SIZE(priv->phymod); n++) {
		struct nfp_phymod *phy = &priv->phymod[priv->phymods];
		int i, err, sff_type;
		const char *cp;

		phy->priv = priv;
		phy->index = n;

		snprintf(phy->key, sizeof(phy->key), "phy%d", n);
		phy->key[sizeof(phy->key)-1] = 0;

		err = _phymod_get_attr_int(phy, "nbi", &phy->nbi);
		if (err < 0)
			continue;

		err = _phymod_get_attr_int(phy, "port", &phy->port);
		if (err < 0)
			continue;

		err = _phymod_get_attr_int(phy, "lanes", &phy->lanes);
		if (err < 0)
			continue;

		cp = _phymod_get_attr(phy, "type");
		if (!cp)
			continue;
		phy->type = _phymod_lookup_type(cp);

		cp = _phymod_get_attr(phy, "label");
		if (cp)
			phy->label = kstrdup(cp, GFP_KERNEL);
		else
			phy->label = kstrdup(phy->key, GFP_KERNEL);

		err = _phymod_get_attr_int(phy, "sff", &sff_type);
		if (err >= 0) {
			for (i = 0; i < ARRAY_SIZE(sff_op_table); i++) {
				if (sff_op_table[i]->type == sff_type) {
					phy->sff.op = sff_op_table[i];
					err = phy->sff.op->open(phy);
					break;
				}
			}
			if (err < 0)
				continue;
			if (i == ARRAY_SIZE(sff_op_table))
				continue;
		}

		priv->phymods++;
	}

	for (n = 0; n < ARRAY_SIZE(priv->eth); n++) {
		struct nfp_phymod_eth *eth = &priv->eth[priv->eths];
		int i, err;
		const char *cp;

		eth->priv = priv;
		eth->index = n;

		snprintf(eth->key, sizeof(eth->key), "eth%d", n);
		eth->key[sizeof(eth->key)-1] = 0;

		err = _eth_get_attr_int(eth, "phy", &i);
		if (err < 0)
			continue;

		if (i < 0 || i >= priv->phymods)
			continue;

		eth->phymod = &priv->phymod[i];

		err = _eth_get_attr_mac(eth, "mac", &eth->mac[0]);
		if (err < 0)
			continue;

		err = _eth_get_attr_int(eth, "lane", &eth->lane);
		if (err < 0)
			continue;

		err = _eth_get_attr_int(eth, "lanes", &eth->lanes);
		if (err < 0)
			continue;

		cp = _eth_get_attr(eth, "label");
		if (cp)
			eth->label = kstrdup(cp, GFP_KERNEL);
		else
			eth->label = kstrdup(eth->key, GFP_KERNEL);

		priv->eths++;
	}

	return priv;
}

static int _phymod_select(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv;
	int i, err = 0;
	
	priv = phy->priv;

	if (priv->selected == phy->index)
		return 0;

	for (i = 0; i < priv->phymods; i++) {
		if (phy->index == priv->phymod[i].index)
			continue;
		if (priv->phymod[i].sff.op &&
		    priv->phymod[i].sff.op->select)
			priv->phymod[i].sff.op->select(&priv->phymod[i], 0);
	}

	if (phy->sff.op && phy->sff.op->select)
		err = phy->sff.op->select(phy, 1);

	if (err >= 0)
		priv->selected = phy->index;

	return err;
}

/**
 * PHY Module enumeration
 * @ingroup nfp6000-only
 *
 * This function allows enumeration of the PHY Modules
 * attached to the system.
 *
 * @param nfp   NFP device
 * @param ptr   Abstract pointer, must be NULL to get the first port
 * @return  On succes: phymod
 * @return  On error: NULL
 */
struct nfp_phymod *nfp_phymod_next(struct nfp_device *nfp, void **ptr)
{
	struct nfp_phymod_priv *priv = nfp_device_private(nfp, _phymod_private);
	struct nfp_phymod *prev = *ptr, *next = NULL;

	if (!priv)
		return NULL;

	if (prev == NULL) {
		if (priv->phymods > 0)
			next = &priv->phymod[0];
	} else {
		next = prev + 1;
		if ((next - &priv->phymod[0]) >= priv->phymods)
			next = NULL;
	}

	*ptr = next;
	return next;
}
EXPORT_SYMBOL(nfp_phymod_next);

/**
 * Get the index for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param index 	Pointer to a int for the index
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_index(struct nfp_phymod *phymod, int *index)
{
	if (index)
		*index = phymod->index;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_get_index);

/**
 * Get the string (UTF8) label for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param label		Pointer to a const char * for the label
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_label(struct nfp_phymod *phymod, const char **label)
{
	if (label)
		*label = phymod->label;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_get_label);


/**
 * Get the NBI ID for a phymode
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param nbi		Pointer to a int for the NBI
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_nbi(struct nfp_phymod *phymod, int *nbi)
{
	if (nbi)
		*nbi = phymod->nbi;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_get_nbi);

/**
 * Get the base port and/or size
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param base		Pointer to a int for base port (0..23)
 * @param size		Pointer to a int for number of ports
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_port(struct nfp_phymod *phymod, int *base, int *size)
{
	if (base)
		*base = phymod->port;

	if (size)
		*size = phymod->lanes;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_get_port);

/**
 * Get the type ID for the port
 * @ingroup nfp6000-only
 *
 * @param phymod
 * @param type		Pointer to a int for the type (see NFP_PHYMOD_TYPE_*)
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_get_type(struct nfp_phymod *phymod, int *type)
{
	int present = 1;

	if (phymod->sff.op && phymod->sff.op->poll_present)
		present = phymod->sff.op->poll_present(phymod);

	if (type)
		*type = present ? phymod->type : NFP_PHYMOD_TYPE_NONE;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_get_type);

/**
 * Report status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the summary
 * status for Transmit Loss of Signal (LOS), Fault, Optical Power,
 * Optical Bias, High/Low Voltage and High/Low Temperature.
 *
 * The returned rxstatus parameter contains the summary status for
 * Receive Loss of Signal (LOS), Fault, Optical Power, High/Low
 * Voltage and High/Low Temperature.
 *
 * For the SFP(+) case these summary statuses are the full status for
 * these alarms.  For CXP and QSFP a detailed per-lane status can be
 * obtained for each of these alarms using the associated
 * type-specific function.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit status summary for the module
 * @param[out] rxstatus Receive status summary for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status(struct nfp_phymod *phy, uint32_t *txstatus,
			   uint32_t *rxstatus)
{
	uint32_t txs = 0, rxs = 0;
	int i, err;
	struct {
		uint32_t flag;
		int (*func)(struct nfp_phymod *p, uint32_t *txs, uint32_t *rxs);
	} status[] = {
		{ NFP_PHYMOD_SUMSTAT_LOS, nfp_phymod_read_status_los },
		{ NFP_PHYMOD_SUMSTAT_FAULT, nfp_phymod_read_status_fault },
		{ NFP_PHYMOD_SUMSTAT_OPTPWR, nfp_phymod_read_status_optpower },
		{ NFP_PHYMOD_SUMSTAT_OPTBIAS, nfp_phymod_read_status_optbias },
		{ NFP_PHYMOD_SUMSTAT_HILOVOLT, nfp_phymod_read_status_voltage },
		{ NFP_PHYMOD_SUMSTAT_HILOTEMP, nfp_phymod_read_status_temp },
	};

	for (i = 0; i < ARRAY_SIZE(status); i++) {
		uint32_t tx, rx;

		err = status[i].func(phy, &tx, &rx);
		if (err >= 0) {
			txs |= tx ? status[i].flag : 0;
			rxs |= rx ? status[i].flag : 0;
		}
	}

	if (txstatus)
		*txstatus = txs;

	if (rxstatus)
		*rxstatus = rxs;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_read_status);

/**
 * Report Loss Of Signal status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status
 * of Transmit Loss of Signal (LOS) for each lane.  For the SFP(+) case
 * the LOS status is in bit zero; for QSFP bits 0-4 and for CXP
 * bits 0-9.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * Loss of Signal (LOS) for each lane.  For the SFP(+) case the LOS
 * status is in bit zero; for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit LOS status for the module
 * @param[out] rxstatus Receive LOS status for the module
 *
 * @return 0 on success. Set errno and return -1 on error.
 *
 */
int nfp_phymod_read_status_los(struct nfp_phymod *phymod, uint32_t *txstatus,
			       uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_los)
		return phymod->sff.op->status_los(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_los);

/**
 * Report Fault status for a PHY module.
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the Transmit
 * Fault status for each lane.  For the SFP(+) case the Fault status is
 * in bit zero; for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * The returned rxstatus parameter indicates the Receive Fault status
 * for each lane.  For the SFP(+) case the LOS status is in bit zero;
 * for QSFP bits 0-4 and for CXP bits 0-9.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Fault status for the module
 * @param[out] rxstatus Receive Fault status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_status_fault(struct nfp_phymod *phymod, uint32_t *txstatus,
				 uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_fault)
		return phymod->sff.op->status_fault(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_fault);

/**
 * Report Optical Power status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit Optical Power for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Power and the
 * LSB for Low Power.  For the SFP(+) case the Optical Power status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * The returned rxstatus parameter indicates the status of
 * Receive Optical Power for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Power and the
 * LSB for Low Power.  For the SFP(+) case the Optical Power status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Optical Power status for the module
 * @param[out] rxstatus Receive Optical Power status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_status_optpower(struct nfp_phymod *phymod,
				    uint32_t *txstatus,
				    uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_power)
		return phymod->sff.op->status_power(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_optpower);

/**
 * Report Optical Bias status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit Optical Bias for each lane.  Two bits are used to
 * represent the status for each lane - the MSB for High Bias and the
 * LSB for Low Bias.  For the SFP(+) case the Optical Bias status will
 * be in bits 0-1; for QSFP bits 0-7 and for CXP bits 0-19.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit Optical Bias status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_status_optbias(struct nfp_phymod *phymod,
				   uint32_t *txstatus, uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_bias)
		return phymod->sff.op->status_bias(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_optbias);

/**
 * Report High/Low Voltage status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit High/Low Voltage alarms for the module.  Two bits are used
 * to represent the status for each monitored voltage - the most
 * significant bit for High Voltage and the least significant bit for
 * Low Voltage.  For the SFP(+) case only one voltage is monitored and
 * the High/Low Voltage status will be in bits 0-1.  For the QSFP and
 * CXP two voltages are monitored Vcc12 and Vcc3.3.  Two bits are used
 * for each voltage - Vcc3.3 status is in bits 0-1; Vcc12 status is in
 * bits 2-3.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * High/Low Voltage for the module.  Two bits are used to represent
 * the status for each monitored voltage - the most significant bit
 * for High Voltage and the least significant bit for Low Voltage.
 * For the SFP(+) case only one voltage is monitored and the High/Low
 * Voltage status will be in bits 0-1.  For the QSFP and CXP two
 * voltages are monitored Vcc12 and Vcc3.3.  Two bits are used for
 * each voltage - Vcc3.3 status is in bits 0-1; Vcc12 status is in
 * bits 2-3.
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit High/Low Voltage status for the module
 * @param[out] rxstatus Receive High/Low Voltage status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_status_voltage(struct nfp_phymod *phymod,
				   uint32_t *txstatus,
				   uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_volt)
		return phymod->sff.op->status_volt(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_voltage);

/**
 * Report High/Low Temperature status for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Transmit High/Low Temperature alarms for the module.  Two bits are
 * used to represent the status for temperature - the most significant
 * bit for High Temperature and the least significant bit for Low
 * Temperature.  For all modules the High/Low Temperature status will
 * be in bits 0-1.
 *
 * The returned rxstatus parameter indicates the status of Receive
 * High/Low Temperature for the module.  Two bits are used to
 * represent the status for temperature - the most significant bit for
 * High Temperature and the least significant bit for Low
 * Temperature. For all modules the High/Low Temperature status will be
 * in bits 0-1.
 *
 *
 * @param phymod PHY module
 * @param[out] txstatus Transmit High/Low Temperature status for the module
 * @param[out] rxstatus Receive High/Low Temperature status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_status_temp(struct nfp_phymod *phymod, uint32_t *txstatus,
				uint32_t *rxstatus)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->status_temp)
		return phymod->sff.op->status_temp(phymod, txstatus, rxstatus);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_status_temp);

/**
 * Read Lane Disable state for a PHY module.
 * @ingroup nfp6000-only
 *
 * The returned txstatus parameter indicates the type of PHY module in
 * the most significant byte.  The other bytes contain the status of
 * Lane Disable for each lane in the module.
 *
 * The SFP(+) supports a hardware TX_DISABLE (bit-0) and a software
 * TX_DISABLE (bit-1).  These are returned in txstatus.
 *
 * The QSFP supports independent Transmit and Receive software
 * disables for each lane.  The Transmit Lane Disable states are
 * returned in txstatus bits 0-3, the Receive Lane Disable states are
 * returned in rxstatus bits 0-3.
 *
 * The CXP supports independent Transmit and Receive software disables
 * for each lane and two software disable modes: an Output Disable and
 * a Lane (Channel) Disable.  The Transmit Lane Disable states are
 * returned in txstatus bits 0-23, the Receive Lane Disable states are
 * returned in rxstatus bits 0-23.
 *
 *
 * @param phymod PHY module
 * @param[out] txstatus Lane Disable status for the module
 * @param[out] rxstatus Lane Disable status for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read_lanedisable(struct nfp_phymod *phymod, uint32_t *txstate,
				uint32_t *rxstate)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->get_lane_dis)
		return phymod->sff.op->get_lane_dis(phymod, txstate, rxstate);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read_lanedisable);

/**
 * Write Lane Disable state for a PHY module.
 * @ingroup nfp6000-only
 *
 * Enable/Disable lanes in a PHY module as specified by the txstates
 * (transmit) and rxstates (receive) parameters.
 *
 * The SFP(+) supports a hardware TX_DISABLE (bit-0) and a software
 * TX_DISABLE (bit-1).  These are specified in txstates.
 *
 * The QSFP supports independent Transmit and Receive software
 * disables for each lane.  The Transmit Lane Disable states are
 * specified in txstates bits 0-3, the Receive Lane Disable states are
 * specified in rxstates bits 0-3.
 *
 * The CXP supports independent Transmit and Receive software disables
 * for each lane and two software disable modes: an Output Disable and
 * a Lane (Channel) Disable.  The Transmit Lane Disable states are
 * specified in txstates bits 0-23, the Receive Lane Disable states are
 * specified in rxstates bits 0-23.
 *
 *
 * @param phymod PHY module
 * @param[in] txstates Lane Disable states for the module
 * @param[in] rxstates Lane Disable states for the module
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_write_lanedisable(struct nfp_phymod *phymod, uint32_t txstate,
				 uint32_t rxstate)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->set_lane_dis)
		return phymod->sff.op->set_lane_dis(phymod, txstate, rxstate);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_write_lanedisable);

/**
 * Read a PHY module address (8-bit).
 * @ingroup nfp6000-only
 *
 * @param phymod PHY module
 * @param[in] addr address
 * @param[out] data return value
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_read8(struct nfp_phymod *phymod, uint32_t addr,
		     uint8_t *data)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->read8)
		return phymod->sff.op->read8(phymod, addr, data);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_read8);

/**
 * Write a PHY module address (8-bit).
 * @ingroup nfp6000-only
 *
 * @param phymod PHY module
 * @param[in] addr address
 * @param[in] data value
 *
 * @return 0 on success, < 0 on error.
 *
 */
int nfp_phymod_write8(struct nfp_phymod *phymod, uint32_t addr,
		      uint8_t data)
{
	_phymod_select(phymod);

	if (phymod->sff.op && phymod->sff.op->write8)
		return phymod->sff.op->write8(phymod, addr, data);

	return -EINVAL;
}
EXPORT_SYMBOL(nfp_phymod_write8);

/**
 * PHY Module Ethernet port enumeration
 * @ingroup nfp6000-only
 *
 * This function allows enumeration of the Ethernet ports
 * attached to a PHY module
 *
 * @param phy   PHY module
 * @param ptr   Abstract pointer, must be NULL to get the first port
 * @return  On succes: phymod
 * @return  On error: NULL
 */
struct nfp_phymod_eth *nfp_phymod_eth_next(struct nfp_device *nfp, struct nfp_phymod *phy, void **ptr)
{
	struct nfp_phymod_priv *priv;
	int i;

	if (phy) {
		if (phy->priv->nfp != nfp)
			return NULL;

		priv = phy->priv;
	} else {
		if (!nfp)
			return NULL;

		priv = nfp_device_private(nfp, _phymod_private);
	}

	if (!ptr)
		return NULL;

	if (!*ptr) {
		for (i = 0; i < priv->eths; i++) {
			if (!phy || priv->eth[i].phymod == phy) {
				*ptr = &priv->eth[i];
				return &priv->eth[i];
			}
		}
		return NULL;
	}

	i = (struct nfp_phymod_eth *)(*ptr) - &priv->eth[0];
	if (i < 0)
		return NULL;

	for (i++; i < priv->eths; i++) {
		if (!phy || priv->eth[i].phymod == phy) {
			*ptr = &priv->eth[i];
			return &priv->eth[i];
		}
	}

	return NULL;
}
EXPORT_SYMBOL(nfp_phymod_eth_next);

/**
 * Get the index for a phymod's eth interface
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param index 	Pointer to a int for the index (unique for all eths)
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_index(struct nfp_phymod_eth *eth, int *index)
{
	if (index)
		*index = eth->index;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_index);

/**
 * Get the MAC address of and ethernet port
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param mac		Pointer to a const uint8_t * for the 6-byte MAC
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_mac(struct nfp_phymod_eth *eth, const uint8_t **mac)
{
	if (mac)
		*mac = &eth->mac[0];

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_mac);

/**
 * Get the string (UTF8) label for a phymod's Ethernet interface
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param label		Pointer to a const char * for the label
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_label(struct nfp_phymod_eth *eth, const char **label)
{
	if (label)
		*label = eth->label;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_label);

/**
 * Get the NBI ID for a phymod's Ethernet interface
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param nbi		Pointer to a int for the NBI
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_nbi(struct nfp_phymod_eth *eth, int *nbi)
{
	if (nbi)
		*nbi = eth->phymod->nbi;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_nbi);

/**
 * Get the base port and/or lanes
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param base		Pointer to a int for base port (0..23)
 * @param lanes		Pointer to a int for number of phy lanes
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_port(struct nfp_phymod_eth *eth, int *base, int *lanes)
{
	if (base)
		*base = eth->phymod->port + eth->lane;

	if (lanes)
		*lanes = eth->lanes;

	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_port);

/**
 * Get the speed of the Ethernet port (in megabits/sec)
 * @ingroup nfp6000-only
 *
 * @param eth		PHY module ethernet interface
 * @param speed		Pointer to a int for speed (in megabits/sec)
 * @return 0 on success, -1 and errno on error
 */
int nfp_phymod_eth_get_speed(struct nfp_phymod_eth *eth, int *speed)
{
	int per_lane;

	if (!speed)
		return 0;

	/* FIXME: Currently assumes SFP = 1G, SFP+ = 10G, QSFP = 40G, etc */
	switch (eth->phymod->type) {
	case NFP_PHYMOD_TYPE_SFP:
		per_lane = 1000;
		break;
	case NFP_PHYMOD_TYPE_SFPP:
	case NFP_PHYMOD_TYPE_QSFP:
	case NFP_PHYMOD_TYPE_CXP:
		per_lane = 10000;
		break;
	default:
		return -EINVAL;
	}

	*speed = per_lane * eth->lanes;
	return 0;
}
EXPORT_SYMBOL(nfp_phymod_eth_get_speed);


/* vim: set shiftwidth=8 noexpandtab: */
