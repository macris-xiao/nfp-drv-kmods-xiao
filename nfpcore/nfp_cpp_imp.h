/*
 * Copyright (C) 2008-2014, Netronome Systems, Inc. All rights reserved.
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
 * vim:shiftwidth=8:noexpandtab
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
 * NFP CPP operations structure
 */
struct nfp_cpp_operations {
	/** Model ID (0 for built-in autodetection) */
	uint32_t model;
	/** Interface ID - required! */
	uint32_t interface;
	/** Serial number, typically the management MAC for the NFP */
	uint8_t serial[6];

	/** Size of priv area in struct nfp_cpp_area */
	size_t area_priv_size;
	size_t event_priv_size;
	struct module *owner;
	struct device *parent;	/* Device handle */
	void *priv;		/* Private data */

	/** Initialize the NFP CPP bus
	 * Called only once, during nfp_cpp_register()
	 */
	int (*init)(struct nfp_cpp *cpp);

	/** Free the bus
	 * Called only once, during nfp_cpp_unregister()
	 */
	void		(*free)(struct nfp_cpp *cpp);

	/** Initialize a new NFP CPP area
	 * NOTE: This is _not_ serialized
	 */
	int (*area_init)(struct nfp_cpp_area *area,
			 uint32_t dest, unsigned long long address,
			 unsigned long size);
	/** Clean up a NFP CPP area before it is freed
	 * NOTE: This is _not_ serialized
	 */
	void (*area_cleanup)(struct nfp_cpp_area *area);

	/** Acquire resources for a NFP CPP area
	 * Serialized
	 */
	int (*area_acquire)(struct nfp_cpp_area *area);
	/** Release resources for a NFP CPP area
	 * Serialized
	 */
	void (*area_release)(struct nfp_cpp_area *area);
	/** Report allocated resource of a NFP CPP area
	 * NOTE: This is _not_ serialized
	 */
	struct resource *(*area_resource)(struct nfp_cpp_area *area);
	/** Return the CPU bus address of a NFP CPP area
	 * NOTE: This is _not_ serialized
	 */
	phys_addr_t (*area_phys)(struct nfp_cpp_area *area);
	/** Return a void IO pointer to a NFP CPP area
	 * NOTE: This is _not_ serialized
	 */
	void __iomem *(*area_iomem)(struct nfp_cpp_area *area);
	/** Perform a read from a NFP CPP area
	 * Serialized
	 */
	int (*area_read)(struct nfp_cpp_area *area, void *kernel_vaddr,
			 unsigned long offset, unsigned int length);
	/** Perform a write to a NFP CPP area
	 * Serialized
	 */
	int (*area_write)(struct nfp_cpp_area *area, const void *kernel_vaddr,
			  unsigned long offset, unsigned int length);

	/** IRQ and event management */

	/** Event management
	 */
	int (*event_acquire)(struct nfp_cpp_event *event, uint32_t match,
			     uint32_t mask, uint32_t type);
	void (*event_release)(struct nfp_cpp_event *event);

	/* Acquire an explicit transaction handle */
	size_t explicit_priv_size;
	int (*explicit_acquire)(struct nfp_cpp_explicit *expl);
	/* Release an explicit transaction handle */
	void (*explicit_release)(struct nfp_cpp_explicit *expl);
	/* Write data to send */
	int (*explicit_put)(struct nfp_cpp_explicit *expl,
			    const void *buff, size_t len);
	/* Read data received */
	int (*explicit_get)(struct nfp_cpp_explicit *expl,
			    void *buff, size_t len);
	/* Perform the transaction */
	int (*explicit_do)(struct nfp_cpp_explicit *expl,
			   const struct nfp_cpp_explicit_command *cmd,
			   uint64_t address);
};

/**
 * Create a NFP CPP handle from an operations structure
 *
 * @param   cpp_ops  NFP CPP operations structure
 * @return           NFP CPP handle on success, NULL on failure
 */
struct nfp_cpp *nfp_cpp_from_operations(
		const struct nfp_cpp_operations *cpp_ops);

/**
 * Return the value of the 'priv' member of the cpp operations
 *
 * @param   cpp     NFP CPP operations structure
 * @return          Opaque private data
 */
void *nfp_cpp_priv(struct nfp_cpp *priv);

/**
 * Get the privately allocated portion of a NFP CPP area handle
 *
 * @param   cpp_area  NFP CPP area handle
 * @return            Pointer to the private area, or NULL on failure
 */
void *nfp_cpp_area_priv(struct nfp_cpp_area *cpp_area);

/**
 * Get the privately allocated portion of a NFP CPP explicit handle
 *
 * @param   cpp_area  NFP CPP explicit handle
 * @return            Pointer to the private area, or NULL on failure
 */
void *nfp_cpp_explicit_priv(struct nfp_cpp_explicit *cpp_explicit);

/**
 * Get the privately allocated portion of a NFP CPP event handle
 *
 * @param   cpp_event  NFP CPP event handle
 * @return             Pointer to the private area, or NULL on failure
 */
void *nfp_cpp_event_priv(struct nfp_cpp_event *cpp_event);

/**
 * KERNEL API:
 * Return the device that is the parent of the NFP CPP bus
 *
 * @param   cpp      NFP CPP operations structure
 * @return           Opaque device pointer
 */

struct device *nfp_cpp_device(struct nfp_cpp *cpp);

#endif /* NFP_CPP_IMP_H */

/*
 * Local variables:
 * c-file-style: "Linux"
 * indent-tabs-mode: t
 * End:
 */
