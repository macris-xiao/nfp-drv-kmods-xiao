/*
 * Copyright (C) 2008-2015, Netronome Systems, Inc. All rights reserved.
 *
 * This software may be redistributed under either of two provisions:
 *
 * 1. The GNU General Public License version 2 (see
 *    http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
 *    COPYING.txt file) when it is used for Linux or other
 *    compatible free software as defined by GNU at
 *    http://www.gnu.org/licenses/license-list.html.
 *
 * 2. Or under a non-free commercial license executed directly with
 *    Netronome. The direct Netronome license does not apply when the
 *    software is used as part of the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * NFP CPP Implementation Specifics
 */

#ifndef NFP_CPP_IMP_H
#define NFP_CPP_IMP_H

struct module;
struct device;

enum nfp_cpp_explicit_reg;
struct nfp_cpp_explicit;

struct nfp_cpp_explicit_command {
	uint32_t cpp_id;
	uint16_t data_ref;
	uint8_t  data_master;
	uint8_t  len;
	uint8_t  byte_mask;
	uint8_t  signal_master;
	uint8_t  signal_ref;
	uint8_t  posted;
	uint8_t  siga;
	uint8_t  sigb;
	int8_t   siga_mode;
	int8_t   sigb_mode;
};

/**
 * struct nfp_cpp_operations - NFP CPP operations structure
 * @model:	Model ID (0 for built-in autodetection) 
 * @interface:	Interface ID - required! 
 * @serial:	Serial number, typically the management MAC for the NFP
 * @area_priv_size:	Size of the nfp_cpp_area private data
 * @event_priv_size:	Size of the nfp_cpp_event private data
 * @owner:	Owner module
 * @parent:	Parent device
 * @priv:	Private data
 * @init:	Initialize the NFP CPP bus, called by nfp_cpp_register()
 * @free:	Free the bus, called during nfp_cpp_unregister()
 * @area_init:	Initialize a new NFP CPP area (not serialized)
 * @area_cleanup:	Clean up a NFP CPP area (not serialized)
 * @area_acquire:	Acquire the NFP CPP area (serialized)
 * @area_release:	Release area (serialized)
 * @area_resource:	Get resource range of area (not serialized)
 * @area_phys:		Get physical address of area (not serialized)
 * @area_iomem:		Get iomem of area (not serialized)
 * @area_read:		Perform a read from a NFP CPP area (serialized)
 * @area_write:		Perform a write to a NFP CPP area (serialized)
 * @event_acquire:	Create an event filter entry
 * @event_release:	Release an event filter entry
 * @explicit_priv_size:	Size of an explicit's private area
 * @explicit_acquire:	Acquire an explicit area
 * @explicit_release:	Release an explicit area
 * @explicit_put:	Write data to send
 * @explicit_get:	Read data received
 * @explicit_do:	Perform the transaction
 */
struct nfp_cpp_operations {
	uint32_t model;
	uint32_t interface;
	uint8_t serial[6];

	size_t area_priv_size;
	size_t event_priv_size;
	struct module *owner;
	struct device *parent;	/* Device handle */
	void *priv;		/* Private data */

	int (*init)(struct nfp_cpp *cpp);
	void		(*free)(struct nfp_cpp *cpp);

	int (*area_init)(struct nfp_cpp_area *area,
			 uint32_t dest, unsigned long long address,
			 unsigned long size);
	void (*area_cleanup)(struct nfp_cpp_area *area);
	int (*area_acquire)(struct nfp_cpp_area *area);
	void (*area_release)(struct nfp_cpp_area *area);
	struct resource *(*area_resource)(struct nfp_cpp_area *area);
	phys_addr_t (*area_phys)(struct nfp_cpp_area *area);
	void __iomem *(*area_iomem)(struct nfp_cpp_area *area);
	int (*area_read)(struct nfp_cpp_area *area, void *kernel_vaddr,
			 unsigned long offset, unsigned int length);
	int (*area_write)(struct nfp_cpp_area *area, const void *kernel_vaddr,
			  unsigned long offset, unsigned int length);

	/* IRQ and event management */

	/* Event management */
	int (*event_acquire)(struct nfp_cpp_event *event, uint32_t match,
			     uint32_t mask, uint32_t type);
	void (*event_release)(struct nfp_cpp_event *event);

	size_t explicit_priv_size;
	int (*explicit_acquire)(struct nfp_cpp_explicit *expl);
	void (*explicit_release)(struct nfp_cpp_explicit *expl);
	int (*explicit_put)(struct nfp_cpp_explicit *expl,
			    const void *buff, size_t len);
	int (*explicit_get)(struct nfp_cpp_explicit *expl,
			    void *buff, size_t len);
	int (*explicit_do)(struct nfp_cpp_explicit *expl,
			   const struct nfp_cpp_explicit_command *cmd,
			   uint64_t address);
};

struct nfp_cpp *nfp_cpp_from_operations(
		const struct nfp_cpp_operations *cpp_ops);
void *nfp_cpp_priv(struct nfp_cpp *priv);
void *nfp_cpp_area_priv(struct nfp_cpp_area *cpp_area);
 
void *nfp_cpp_explicit_priv(struct nfp_cpp_explicit *cpp_explicit);
void *nfp_cpp_event_priv(struct nfp_cpp_event *cpp_event);
struct device *nfp_cpp_device(struct nfp_cpp *cpp);

#endif /* NFP_CPP_IMP_H */
