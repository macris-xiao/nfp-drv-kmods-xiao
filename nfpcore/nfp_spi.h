/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_SPI_H
#define NFP_SPI_H

struct nfp_spi;

/**
 * Acquire a handle to one of the NFP SPI busses
 * @ingroup nfp6000-only
 *
 * @param       nfp     NFP Device
 * @param       bus     SPI Bus (0..3)
 * @param       width   SPI Bus Width (0 (default), 1 bit, 2 bit, or 4 bit)
 */
struct nfp_spi *nfp_spi_acquire(struct nfp_device *nfp, int bus, int width);

/**
 * Release the handle to a NFP SPI bus
 * @ingroup nfp6000-only
 *
 * @param       spi     NFP SPI bus
 */
void nfp_spi_release(struct nfp_spi *spi);

/**
 * Set the clock rate of the NFP SPI bus
 * @ingroup nfp6000-only
 *
 * @param       spi     NFP SPI bus
 * @param       hz      SPI clock rate (-1 = default speed)
 */
int nfp_spi_speed_set(struct nfp_spi *spi, int hz);

/**
 * Get the clock rate of the NFP SPI bus
 * @ingroup nfp6000-only
 *
 * @param       spi     NFP SPI bus
 * @param       hz      SPI clock rate pointer
 */
int nfp_spi_speed_get(struct nfp_spi *spi, int *hz);

/**
 * Set the SPI mode
 * @ingroup nfp6000-only
 *
 * @param       spi     NFP SPI bus
 * @param       mode    SPI CPHA/CPOL mode (-1, 0, 1, 2, or 3)
 *
 * Use mode of '-1' for the default for this bus.
 */
int nfp_spi_mode_set(struct nfp_spi *spi, int mode);

/**
 * Get the SPI mode
 * @ingroup nfp6000-only
 *
 * @param       spi     NFP SPI bus
 * @param       mode    SPI CPHA/CPOL mode pointer
 */
int nfp_spi_mode_get(struct nfp_spi *spi, int *mode);

/**
 * Perform an arbitrary SPI transaction'
 * @ingroup nfp6000-only
 *
 * @param       spi                      SPI Bus
 * @param       cs                       SPI Chip select (0..3)
 * @param       tx                       TX buffer
 * @param       tx_bit_cnt               TX buffer size in bits
 * @param       rx                       RX buffer
 * @param       rx_bit_cnt               RX buffer size in bits
 * @param       mdio_data_drive_disable  MDIO compatibility flag
 */
#define CS_SELECT       (1 << 0)
#define CS_DESELECT     (1 << 1)
int nfp6000_spi_transact(struct nfp_spi *spi, int cs, int cs_action,
                            const void *tx, uint32_t tx_bit_cnt,
                                  void *rx, uint32_t rx_bit_cnt,
                            int mdio_data_drive_disable);

/**
 * Perform a trivial SPI read
 * @ingroup nfp6000-only
 *
 * @param       spi     SPI Bus
 * @param       cs      SPI Chip select (0..3)
 * @param       cmd_len Number of bytes in the command
 * @param       cmd     SPI command
 * @param       res_len Number of bytes of response
 * @param       res     SPI response
 */
int nfp_spi_read(struct nfp_spi *spi, int cs,
                    unsigned int cmd_len, const void *cmd,
                    unsigned int res_len, void *res);

/**
 * Perform a trivial SPI write
 * @ingroup nfp6000-only
 *
 * @param       spi     SPI Bus
 * @param       cs      SPI Chip select (0..3)
 * @param       cmd_len Number of bytes in the command
 * @param       cmd     SPI command
 * @param       dat_len Number of bytes of write data
 * @param       dat     SPI write data
 */
int nfp_spi_write(struct nfp_spi *spi, int cs,
                    unsigned int cmd_len, const void *cmd,
                    unsigned int dat_len, const void *dat);


#endif /* NFP_SPI_H */
/* vim: set shiftwidth=4 expandtab:  */
