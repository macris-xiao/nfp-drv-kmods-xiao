/*
 * Copyright (C) 2014, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_GPIO_H
#define NFP_GPIO_H

#include "nfp.h"

/**
 * GPIO Pin Count
 *
 * @param dev           NFP device
 *
 * @return total number of GPIO pins for this model, or -1 and errno.
 */
int nfp_gpio_pins(struct nfp_device *dev);

/**
 * GPIO Pin Setup
 *
 * @param dev           NFP device
 * @param pin           GPIO Pin
 * @param is_output     0 = input, 1 = output
 *
 * @return 0 on success, or -1 on error (and set errno accordingly).
 *
 * pin is 0..11 on NFP3200 models, and 0..31 on NFP6000 models.
 *
 */
int nfp_gpio_direction(struct nfp_device *dev, int pin, int is_output);

/**
 * GPIO Get Pin Direction
 *
 * @param dev       NFP device
 * @param pin       GPIO Pin (0 .. X)
 * @param is_output 0 = input, 1 = output
 * @return      Error code
 */
int nfp_gpio_get_direction(struct nfp_device *dev, int pin, int *is_output);

/**
 * GPIO Pin Input
 *
 * @param dev		NFP device
 * @param gpio_pin	GPIO Pin
 *
 * @return value of pin, or -1 on error (and set errno accordingly).
 *
 * gpio_pin is 0..11 on NFP3200 models, and 0..31 on NFP6000 models.
 *
 */
int nfp_gpio_get(struct nfp_device *dev, int gpio_pin);

/**
 * GPIO Pin Output
 *
 * @param dev		NFP device
 * @param gpio_pin	GPIO Pin
 * @param value		0, 1
 *
 * @return 0 on success, or -1 on error (and set errno accordingly).
 *
 * gpio_pin is 0..11 on NFP3200 models, and 0..31 on NFP6000 models.
 *
 */
int nfp_gpio_set(struct nfp_device *dev, int gpio_pin, int value);


#endif /* NFP_GPIO_H */
/* vim: set shiftwidth=8 noexpandtab:  */
