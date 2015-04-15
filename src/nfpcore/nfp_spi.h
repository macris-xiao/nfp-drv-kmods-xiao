/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_SPI_H
#define NFP_SPI_H

#include <linux/bitops.h>

#define CS_SELECT       BIT(0)
#define CS_DESELECT     BIT(1)

struct nfp_spi;

struct nfp_spi *nfp_spi_acquire(struct nfp_device *nfp, int bus, int width);
void nfp_spi_release(struct nfp_spi *spi);
int nfp_spi_speed_set(struct nfp_spi *spi, int hz);
int nfp_spi_speed_get(struct nfp_spi *spi, int *hz);
int nfp_spi_mode_set(struct nfp_spi *spi, int mode);
int nfp_spi_mode_get(struct nfp_spi *spi, int *mode);

int nfp6000_spi_transact(struct nfp_spi *spi, int cs, int cs_action,
			 const void *tx, uint32_t tx_bit_cnt,
			 void *rx, uint32_t rx_bit_cnt,
			 int mdio_data_drive_disable);

int nfp_spi_read(struct nfp_spi *spi, int cs,
		 unsigned int cmd_len, const void *cmd,
		 unsigned int res_len, void *res);

int nfp_spi_write(struct nfp_spi *spi, int cs,
		  unsigned int cmd_len, const void *cmd,
		  unsigned int dat_len, const void *dat);

#endif /* NFP_SPI_H */
