/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/time.h>

#include "nfp.h"
#include "nfp_spi.h"

#include "nfp6000/nfp6000.h"

struct nfp_spi {
	struct nfp_cpp *cpp;
	struct nfp_cpp_area *csr;
	int mode;
	int clkdiv;
	int bus;
	int width;
	int key;
};

#define NFP_ARM_SPI                                          (0x403c00)

#define NFP_SPI_TIMEOUT_MS         100

/* NFP6000 SPI CONTROLLER defines */
#define NFP_SPI_PORTMC(x)    (0x10+(((x)&3)<<2))
#define   NFP_SPI_PORTMC_DATADRIVEDISABLE                 BIT(31)
#define   NFP_SPI_PORTMC_CLOCKIDLE                        BIT(29)
#define   NFP_SPI_PORTMC_SELECT(_x)                       (((_x) & 0xf) << 24)
#define   NFP_SPI_PORTMC_DATAWIDTH(_x)                    (((_x) & 0x3) << 20)
#define   NFP_SPI_PORTMC_DATAINTRAIL                      BIT(19)
#define   NFP_SPI_PORTMC_DATAINLEAD                       BIT(18)
#define   NFP_SPI_PORTMC_DATAOUTTRAIL                     BIT(17)
#define   NFP_SPI_PORTMC_DATAOUTLEAD                      BIT(16)
#define   NFP_SPI_PORTMC_CLOCKDISABLE                     BIT(15)
#define   NFP_SPI_PORTMC_CLOCKEDGECOUNT(_x)               (((_x) & 0x7f) << 8)
#define NFP_SPI_PORTCFG(x)   (0x00+(((x)&3)<<2))
#define   NFP_SPI_PORTCFG_MODE                            BIT(31)
#define     NFP_SPI_PORTCFG_MODE_AUTOMATIC                (0 << 31)
#define     NFP_SPI_PORTCFG_MODE_MANUAL                   BIT(31)
#define NFP_SPI_PORTMDO(x)   (0x20+(((x)&3)<<2))
#define NFP_SPI_PORTMDI(x)   (0x30+(((x)&3)<<2))
#define NFP_SPI_SPIIOCONFIG                                  0x00000100
#define NFP_SPI_SPIIOIDLESTATUS                              0x00000104
#define NFP_SPI_WE                         0x0000010c
#define   NFP_SPI_WE_AVAILABLE  BIT(4)
#define   NFP_SPI_WE_WRITEENABLETARGET(_x) (((_x) & 0xf) << 0)
#define   NFP_SPI_PORTCFG_BUSY                            BIT(30)

#define VALID_CS(cs)            ((cs >= 0) && (cs <= 3))
#define CS_OFF                  NFP_SPI_PORTMC_SELECT(0xf)
#define CS_BITS(cs)                                       \
		((VALID_CS(cs)) ?                         \
		NFP_SPI_PORTMC_SELECT((0xf & ~(1 << cs))) \
		: CS_OFF)

#define SPIMODEBITS(s)                                                \
	((s->mode & BIT(1) ? NFP_SPI_PORTMC_CLOCKIDLE : 0) |        \
	 (s->mode & BIT(0)                                          \
	  ? (NFP_SPI_PORTMC_DATAINTRAIL | NFP_SPI_PORTMC_DATAOUTLEAD) \
	  : (NFP_SPI_PORTMC_DATAINLEAD | NFP_SPI_PORTMC_DATAOUTTRAIL)))

#define CPHA(mode)  (mode & 1)

#define NFP6_SPI_DEFAULT_CTRL(edges, spi)          \
	(SPIMODEBITS(spi)                          \
	 | NFP_SPI_PORTMC_DATAWIDTH(spi->width)    \
	 | (spi)->clkdiv                           \
	 | NFP_SPI_PORTMC_CLOCKEDGECOUNT(edges))

#define SET_EDGE_COUNT(ctrl, cnt) \
	do {                                                    \
		ctrl &= ~0x7f00;                                \
		ctrl |= NFP_SPI_PORTMC_CLOCKEDGECOUNT(cnt);     \
	} while (0)

#define SPI_DEFAULT_MODE        (BIT(1)|BIT(0))	/* SPI_MODE3 */
#define SPIXDAT23_OFFS          8
#define SPI_MAX_BITS_PER_CTRL_WRITE 32

/* SPI source clock is PCLK(1GHz), the clock divider bits are
 * the count of PCLKs per SPI half-cycle, 8bits of divider give
 * a range 1-256 per half cycle or 2-512 per cycle, giving a
 * clock range of 500MHz down to ~2MHz
 *
 * pclk_freq(1000MHz) / (2 * (1 + pclk_half_cycle_count_bits)) = spi_freq
 */
#define MHZ(x)                  ((x) * 1000 * 1000)
#define PCLK_HZ                MHZ(1000)
#define MIN_SPI_HZ              ((PCLK_HZ / 512))	/*   ~2MHz */
#define MAX_SPI_HZ              ((PCLK_HZ /   2))	/* ~500MHz */
#define DEF_SPI_HZ              MHZ(5)

static int nfp6000_spi_csr_readl(struct nfp_spi *spi, uint32_t csr,
				 uint32_t *val)
{
	return nfp_cpp_area_readl(spi->csr, csr, val);
}

static int nfp6000_spi_csr_writel(struct nfp_spi *spi, uint32_t csr,
				  uint32_t val)
{
	return nfp_cpp_area_writel(spi->csr, csr, val);
}

/******************************************************************************/

#define offset_of(s, e)         ((intptr_t)&((s *)NULL)->e)

/******************************************************************************/

static int nfp6000_spi_run_clock(struct nfp_spi *spi, uint32_t control)
{
	uint32_t tmp;
	int err;
	struct timespec ts, timeout = {
		.tv_sec = NFP_SPI_TIMEOUT_MS / 1000,
		.tv_nsec = (NFP_SPI_TIMEOUT_MS % 1000) * 1000000,
	};

	err = nfp6000_spi_csr_writel(spi, NFP_SPI_PORTMC(spi->bus), control);
	if (err < 0)
		return err;

	ts = CURRENT_TIME;
	timeout = timespec_add(ts, timeout);

	for (ts = CURRENT_TIME;
	     timespec_compare(&ts, &timeout) < 0; ts = CURRENT_TIME) {
		err =
		    nfp6000_spi_csr_readl(spi, NFP_SPI_PORTCFG(spi->bus),
					  &tmp);
		if (err < 0)
			return err;

		if (!(tmp & NFP_SPI_PORTCFG_BUSY))
			return 0;
	}

	return -ETIMEDOUT;
}

static int nfp_spi_set_pin_association(struct nfp_spi *spi, int port, int pin)
{
	unsigned int val;
	int err;

	err = nfp6000_spi_csr_readl(spi, NFP_SPI_SPIIOCONFIG, &val);
	if (err < 0)
		return err;
	val &= ~(0x3 << (2 * ((pin & 3) - 1)));
	val |= (port & 3) << (2 * ((pin & 3) - 1));

	return nfp6000_spi_csr_writel(spi, NFP_SPI_SPIIOCONFIG, val);
}

static int do_first_bit_cpha0_hack(struct nfp_spi *spi, uint32_t ctrl,
				   uint32_t mdo)
{
	uint32_t control = ctrl | NFP_SPI_PORTMC_CLOCKDISABLE;

	SET_EDGE_COUNT(control, 1);

	return nfp6000_spi_run_clock(spi, control);
}

static int nfp6000_spi_cs_control(struct nfp_spi *spi, int cs, uint32_t enable)
{
	uint32_t ctrl = NFP6_SPI_DEFAULT_CTRL(4, spi) |
	    NFP_SPI_PORTMC_CLOCKDISABLE;

	ctrl |= (enable) ? CS_BITS(cs) : CS_OFF;

	return nfp6000_spi_run_clock(spi, ctrl);
}

static int nfp6000_spi_set_manual_mode(struct nfp_spi *spi)
{
	uint32_t tmp;
	int err;

	err = nfp6000_spi_csr_readl(spi, NFP_SPI_PORTCFG(spi->bus), &tmp);
	if (err < 0)
		return err;
	tmp |= NFP_SPI_PORTCFG_MODE_MANUAL;
	return nfp6000_spi_csr_writel(spi, NFP_SPI_PORTCFG(spi->bus), tmp);
}

#define SPI0_CLKIDLE_OFFS   0
#define SPI1_CLKIDLE_OFFS   4
#define SPI2_CLKIDLE_OFFS   8
#define SPI3_CLKIDLE_OFFS   10
static int nfp6000_spi_set_clk_pol(struct nfp_spi *spi)
{
	int err;
	unsigned int val;
	unsigned int polbit_offset[] = { SPI0_CLKIDLE_OFFS, SPI1_CLKIDLE_OFFS,
		SPI2_CLKIDLE_OFFS, SPI3_CLKIDLE_OFFS
	};
	err = nfp6000_spi_csr_readl(spi, NFP_SPI_SPIIOIDLESTATUS, &val);
	if (err < 0)
		return err;
	val &= ~(1 << (polbit_offset[spi->bus & 3]));
	val |= ((spi->mode & 1) << (polbit_offset[spi->bus & 3]));

	return nfp6000_spi_csr_writel(spi, NFP_SPI_SPIIOIDLESTATUS, val);
}

#define BITS_TO_BYTES(x)    (((x) + 7) / 8)
int nfp6000_spi_transact(struct nfp_spi *spi, int cs, int cs_action,
			 const void *tx, uint32_t tx_bit_cnt,
			 void *rx, uint32_t rx_bit_cnt,
			 int mdio_data_drive_disable)
{
	int err = 0;
	int first_tx_bit = 1;
	uint32_t i, tmp, ctrl, clk_bit_cnt;
	uint8_t *_tx, *_rx;
	uint32_t txbits, rxbits;

	ctrl = SPIMODEBITS(spi);
	ctrl |=
	    NFP_SPI_PORTMC_DATAWIDTH(spi->width) | spi->clkdiv | CS_BITS(cs);

	if (mdio_data_drive_disable && !tx) {
		/* used only for MDIO compatibility/implementation
		 * via this routine
		 */
		ctrl |= NFP_SPI_PORTMC_DATADRIVEDISABLE;
	}

	if (VALID_CS(cs) && (cs_action & CS_SELECT)) {
		if (cs > 0)
			nfp_spi_set_pin_association(spi, spi->bus, cs);
		err = nfp6000_spi_cs_control(spi, cs, 1);
		if (err < 0)
			return err;
	}

	_tx = (uint8_t *)tx;
	_rx = (uint8_t *)rx;
	while ((tx_bit_cnt > 0) || (rx_bit_cnt > 0)) {
		txbits =
		    min_t(uint32_t, SPI_MAX_BITS_PER_CTRL_WRITE, tx_bit_cnt);
		rxbits =
		    min_t(uint32_t, SPI_MAX_BITS_PER_CTRL_WRITE, rx_bit_cnt);
		clk_bit_cnt = max_t(uint32_t, rxbits, txbits);
		if (clk_bit_cnt < SPI_MAX_BITS_PER_CTRL_WRITE)
			clk_bit_cnt = (clk_bit_cnt + 7) & ~7;

		SET_EDGE_COUNT(ctrl, 2 * clk_bit_cnt);

		if (txbits) {
			if (txbits % 8)
				_tx[txbits / 8] |=
				    ((1 << (8 - (txbits % 8))) - 1);
			for (i = 0, tmp = 0; i < BITS_TO_BYTES(txbits);
			     i++, _tx++)
				tmp |= (_tx[0] << (24 - (i * 8)));
			for (; i < BITS_TO_BYTES(SPI_MAX_BITS_PER_CTRL_WRITE);
			     i++, _tx++)
				tmp |= (0xff << (24 - (i * 8)));
		} else {
			tmp = 0xffffffff;
		}
		err =
		    nfp6000_spi_csr_writel(spi, NFP_SPI_PORTMDO(spi->bus),
					   tmp);
		if (err < 0)
			return err;

		if (first_tx_bit && CPHA(spi->mode) == 0) {
			do_first_bit_cpha0_hack(spi, ctrl, tmp);
			first_tx_bit = 0;
		}

		err = nfp6000_spi_run_clock(spi, ctrl);
		if (err < 0)
			return err;

		if (rxbits) {
			err =
			    nfp6000_spi_csr_readl(spi,
						  NFP_SPI_PORTMDI(spi->bus),
						  &tmp);
			if (err < 0)
				return err;
			if (clk_bit_cnt < SPI_MAX_BITS_PER_CTRL_WRITE)
				tmp =
				    tmp << (SPI_MAX_BITS_PER_CTRL_WRITE -
					    clk_bit_cnt);

			for (i = 0; i < BITS_TO_BYTES(rxbits); i++, _rx++)
				_rx[0] = (tmp >> (24 - (i * 8))) & 0xff;
		}
		tx_bit_cnt -= txbits;
		rx_bit_cnt -= rxbits;
	}

	if (VALID_CS(cs) && (cs_action & CS_DESELECT))
		err = nfp6000_spi_cs_control(spi, cs, 0);

	return err;
}

int nfp_spi_read(struct nfp_spi *spi, int cs,
		 unsigned int cmd_len, const void *cmd,
		 unsigned int res_len, void *res)
{
	int err;

	err = nfp6000_spi_transact(spi, cs, CS_SELECT,
				   cmd, cmd_len * 8, NULL, 0, 0);
	if (err < 0)
		return err;

	return nfp6000_spi_transact(spi, cs, CS_DESELECT,
				    NULL, 0, res, res_len * 8, 0);
}

int nfp_spi_write(struct nfp_spi *spi, int cs,
		  unsigned int cmd_len, const void *cmd,
		  unsigned int dat_len, const void *dat)
{
	int err;

	err = nfp6000_spi_transact(spi, cs, CS_SELECT,
				   cmd, cmd_len * 8, NULL, 0, 0);
	if (err < 0)
		return err;

	return nfp6000_spi_transact(spi, cs, CS_DESELECT,
				    dat, dat_len * 8, NULL, 0, 0);
}

static inline int spi_interface_key(uint16_t interface)
{
	switch (NFP_CPP_INTERFACE_TYPE_of(interface)) {
	case NFP_CPP_INTERFACE_TYPE_ARM:
		return 1;
	case NFP_CPP_INTERFACE_TYPE_PCI:
		return NFP_CPP_INTERFACE_UNIT_of(interface) + 2;
	default:
		return -EINVAL;
	}
}

/* Acquire a handle to one of the NFP SPI busses
 *
 * @param       nfp     NFP Device
 * @param       bus     SPI Bus (0..3)
 * @param       width   SPI Bus Width (0 (default), 1 bit, 2 bit, or 4 bit)
 */
struct nfp_spi *nfp_spi_acquire(struct nfp_device *nfp, int bus, int width)
{
	struct nfp_spi *spi;
	struct nfp_cpp *cpp;
	int err, key;
	uint32_t val;
	int timeout = 5 * 1000;	/* 5s */

	if (width != 0 && width != 1 && width != 2 && width != 4)
		return ERR_PTR(-EINVAL);

	cpp = nfp_device_cpp(nfp);
	key = spi_interface_key(nfp_cpp_interface(cpp));
	if (key < 0)
		return ERR_PTR(key);

	spi = kzalloc(sizeof(*spi), GFP_KERNEL);
	if (!spi)
		return ERR_PTR(-ENOMEM);

	spi->cpp = cpp;
	spi->key = key;
	spi->mode = SPI_DEFAULT_MODE;
	spi->bus = bus;
	spi->width = (width == 0 || width == 1) ? 1 : (width == 2) ? 2 : 3;

	spi->csr = nfp_cpp_area_alloc_acquire(spi->cpp,
					      NFP_CPP_ID(NFP_CPP_TARGET_ARM,
							 NFP_CPP_ACTION_RW, 0),
					      NFP_ARM_SPI, 0x400);

	if (!spi->csr) {
		kfree(spi);
		return ERR_PTR(-ENOMEM);
	}

	/* Is it locked? */
	for (; timeout > 0; timeout -= 100) {
		nfp6000_spi_csr_writel(spi, NFP_SPI_WE,
				       spi->key);
		nfp6000_spi_csr_readl(spi, NFP_SPI_WE, &val);
		if (val == spi->key)
			break;
		if (msleep_interruptible(100) != 100) {
			nfp_cpp_area_release_free(spi->csr);
			kfree(spi);
			return ERR_PTR(-EINTR);
		}
	}

	/* Unable to claim the SPI device lock? */
	if (timeout <= 0) {
		nfp_cpp_area_release_free(spi->csr);
		kfree(spi);
		return ERR_PTR(-EBUSY);
	}

	/* DAT1(SPI MISO) is disabled(configured as SPI port 0 DAT2/3)
	 * by default for SPI ports 2 and 3
	 */
	if (bus > 1) {
		err = nfp6000_spi_csr_readl(spi, NFP_SPI_SPIIOCONFIG, &val);
		if (err < 0) {
			kfree(spi);
			return ERR_PTR(err);
		}
		val &= ~(3 << SPIXDAT23_OFFS);
		val |= ((bus & 3) << SPIXDAT23_OFFS);
		err = nfp6000_spi_csr_writel(spi, NFP_SPI_SPIIOCONFIG, val);
		if (err < 0) {
			nfp_cpp_area_release_free(spi->csr);
			kfree(spi);
			return ERR_PTR(err);
		}
	}

	nfp_spi_speed_set(spi, DEF_SPI_HZ);
	err = nfp6000_spi_set_manual_mode(spi);
	if (err < 0) {
		nfp_cpp_area_release_free(spi->csr);
		kfree(spi);
		return ERR_PTR(err);
	}

	nfp6000_spi_set_clk_pol(spi);
	return spi;
}

/* Release the handle to a NFP SPI bus
 *
 * @param       spi     NFP SPI bus
 */
void nfp_spi_release(struct nfp_spi *spi)
{
	nfp6000_spi_csr_writel(spi, NFP_SPI_WE,
			       NFP_SPI_WE_AVAILABLE);
	nfp_cpp_area_release_free(spi->csr);
	kfree(spi);
}

/* Set the clock rate of the NFP SPI bus
 *
 * @param       spi     NFP SPI bus
 * @param       hz      SPI clock rate (-1 = default speed)
 */
int nfp_spi_speed_set(struct nfp_spi *spi, int hz)
{
	if (hz < 0)
		hz = DEF_SPI_HZ;

	if (hz < MIN_SPI_HZ || hz > MAX_SPI_HZ)
		return -EINVAL;

	/* clkdiv = PCLK_HZ / 2 / hz - 1 */
	spi->clkdiv = PCLK_HZ / 2 / hz - 1;

	return 0;
}

/* Get the clock rate of the NFP SPI bus
 *
 * @param       spi     NFP SPI bus
 * @param       hz      SPI clock rate pointer
 */
int nfp_spi_speed_get(struct nfp_spi *spi, int *hz)
{
	if (hz)
		*hz = PCLK_HZ / 2 / (spi->clkdiv + 1);

	return 0;
}

/* Set the SPI mode
 *
 * @param       spi     NFP SPI bus
 * @param       mode    SPI CPHA/CPOL mode (-1, 0, 1, 2, or 3)
 *
 * Use mode of '-1' for the default for this bus.
 */
int nfp_spi_mode_set(struct nfp_spi *spi, int mode)
{
	if (mode < -1 || mode > 3)
		return -EINVAL;

	spi->mode = (mode == -1) ? SPI_DEFAULT_MODE : mode;
	nfp6000_spi_set_clk_pol(spi);

	return 0;
}

/* Get the SPI mode
 *
 * @param       spi     NFP SPI bus
 * @param       mode    SPI CPHA/CPOL mode pointer
 */
int nfp_spi_mode_get(struct nfp_spi *spi, int *mode)
{
	if (mode)
		*mode = spi->mode;

	return 0;
}

/* vim: set shiftwidth=8 noexpandtab:  */
