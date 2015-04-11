/*
 * Copyright (C) 2015 Netronome Systems, Inc. All rights reserved.
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 *
 * QSFP support
 */

/* Included from nfp_nbi_phymod.c - not compiled separately! */
#ifdef NFP_NBI_PHYMOD_C

/* SFF-8431 operations - built off of the SFF-8431 operations */
struct sff_8431 {
	struct sff_bus bus;
	int selected;
	int page;
	int tx_disable;
	struct {
		pin_t present;
		pin_t rx_los;
		pin_t tx_fault;
	} in;
	struct {
		pin_t tx_disable;
	} out;
};

static int sff_8431_open(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8431 *sff;
	int err;

	sff = kzalloc(sizeof(*sff), GFP_KERNEL);
	if (!sff)
		return -ENOMEM;

	sff->selected = 0;
	sff->page = -1;

	err = _phymod_get_attr_pin(phy, "pin.present", &sff->in.present);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_pin(phy, "pin.tx_fault", &sff->in.tx_fault);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_pin(phy, "pin.rx_los", &sff->in.rx_los);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_pin(phy, "pin.tx_disable", &sff->out.tx_disable);
	if (err < 0)
		goto exit;

	err = pin_direction(priv->nfp, &sff->in.present, 0);
	if (err < 0)
		goto exit;

	err = pin_direction(priv->nfp, &sff->in.tx_fault, 0);
	if (err < 0)
		goto exit;

	err = pin_direction(priv->nfp, &sff->in.rx_los, 0);
	if (err < 0)
		goto exit;

	err = pin_direction(priv->nfp, &sff->out.tx_disable, 1);
	if (err < 0)
		goto exit;

	err = _phymod_get_attr_bus(phy, "SFF-8431", &sff->bus);
	if (err < 0)
		goto exit;

	phy->sff.priv = sff;

	return 0;

exit:
	kfree(sff);
	return err;
}

static void sff_8431_close(struct nfp_phymod *phy)
{
	struct sff_8431 *sff = phy->sff.priv;

	phy->sff.op->select(phy, 0);
	if (sff->bus.op && sff->bus.op->close)
		sff->bus.op->close(&sff->bus);

	kfree(sff);
}

static int sff_8431_poll_present(struct nfp_phymod *phy)
{
	struct nfp_phymod_priv *priv = phy->priv;
	struct sff_8431 *sff = phy->sff.priv;
	int err;

	err = pin_get(priv->nfp, &sff->in.present);
	if (err < 0)
		return err;

	return err ? 0 : 1;
}

static int sff_8431_select(struct nfp_phymod *phy, int is_selected)
{
	struct sff_8431 *sff = phy->sff.priv;
	int err;

	if (sff->bus.op && sff->bus.op->select) {
		err = sff->bus.op->select(&sff->bus, is_selected);
		if (err < 0)
			return err;
	}

	sff->selected = is_selected;

	return 0;
}

static int sff_8431_read8(struct nfp_phymod *phy, uint32_t reg, uint8_t *val)
{
	struct sff_8431 *sff = phy->sff.priv;
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

static int sff_8431_write8(struct nfp_phymod *phy, uint32_t reg, uint8_t val)
{
	struct sff_8431 *sff = phy->sff.priv;
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

static int sff_8431_status_los(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	struct sff_8431 *sff = phy->sff.priv;
	int err;

	err = pin_get(phy->priv->nfp, &sff->in.rx_los);
	if (err < 0)
		return err;

	if (tx_status)
		*tx_status = 0;

	if (rx_status)
		*rx_status = err;

	return 0;
}

static int sff_8431_status_fault(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	struct sff_8431 *sff = phy->sff.priv;
	int err;

	err = pin_get(phy->priv->nfp, &sff->in.tx_fault);
	if (err < 0)
		return err;

	if (tx_status)
		*tx_status = err;

	if (rx_status)
		*rx_status = 0;

	return 0;
}

static int sff_8431_get_lane_dis(struct nfp_phymod *phy,
			       uint32_t *tx_status, uint32_t *rx_status)
{
	struct sff_8431 *sff = phy->sff.priv;
	uint32_t rxs = 0, txs = 0;

	txs = sff->tx_disable;

	if (tx_status)
		*tx_status = txs;

	if (rx_status)
		*rx_status = rxs;

	return 0;
}

static int sff_8431_set_lane_dis(struct nfp_phymod *phy,
			         uint32_t tx_status, uint32_t rx_status)
{
	struct sff_8431 *sff = phy->sff.priv;
	int err;
	
	err = pin_set(phy->priv->nfp, &sff->out.tx_disable, tx_status & 1);
	if (err < 0)
		return err;

	sff->tx_disable = tx_status & 1;
	return 0;
}

static const struct sff_ops sff_8431_ops = {
	.type = 8431,
	.open = sff_8431_open,
	.close = sff_8431_close,
	.select = sff_8431_select,

	.poll_present = sff_8431_poll_present,
	.status_los = sff_8431_status_los,
	.status_fault = sff_8431_status_fault,

	.read8 = sff_8431_read8,
	.write8 = sff_8431_write8,

	.set_lane_dis = sff_8431_set_lane_dis,
	.get_lane_dis = sff_8431_get_lane_dis,
};

#endif /* NFP_NBI_PHYMOD_C */
