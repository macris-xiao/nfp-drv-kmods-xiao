/*
 * Copyright (C) 2014-2015, Netronome Systems, Inc.
 * All right reserved.
 *
 */

#ifndef NFP_GPIO_H
#define NFP_GPIO_H

#include "nfp.h"

int nfp_gpio_pins(struct nfp_device *dev);
int nfp_gpio_direction(struct nfp_device *dev, int pin, int is_output);
int nfp_gpio_get_direction(struct nfp_device *dev, int pin, int *is_output);
int nfp_gpio_get(struct nfp_device *dev, int gpio_pin);
int nfp_gpio_set(struct nfp_device *dev, int gpio_pin, int value);

#endif /* NFP_GPIO_H */
