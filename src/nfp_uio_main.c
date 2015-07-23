/*
 * Copyright (C) 2015 Netronome Systems, Inc. All rights reserved.
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
 * @file dpdk/kernel/nfp_uio.c
 *
 * Netronome DPDK uio kernel module
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/io.h>
#include <linux/msi.h>
#include <linux/version.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp3200_pcie.h"
#include "nfpcore/nfp6000_pcie.h"
#include "nfpcore/nfp_dev_cpp.h"


#ifndef PCI_MSIX_ENTRY_SIZE
#define PCI_MSIX_ENTRY_SIZE             16
#define PCI_MSIX_ENTRY_LOWER_ADDR       0
#define PCI_MSIX_ENTRY_UPPER_ADDR       4
#define PCI_MSIX_ENTRY_DATA             8
#define PCI_MSIX_ENTRY_VECTOR_CTRL      12
#define PCI_MSIX_ENTRY_CTRL_MASKBIT     1
#endif

/* Ideally we should support two types of interrupts:
 *
 *	- Link Status Change Interrupt
 *	- Exception Interrupt
 *
 * But the uio Linux kernel interface just admits one interupt per uio device.
 */
#define NFP_NUM_MSI_VECTORS 1

/* interrupt mode */
enum nfp_uio_intr_mode {
    NFP_UIO_LEGACY_INTR_MODE = 0,
    NFP_UIO_MSI_INTR_MODE,
    NFP_UIO_MSIX_INTR_MODE,
};

/*
 * A structure describing the private information for a uio device.
 */
struct nfp_uio_pci_dev {
    struct uio_info info;
    struct pci_dev *pdev;
    /* spinlock for accessing PCI config space or msix
     * data in multi tasks/isr
     */
    spinlock_t lock;
    enum nfp_uio_intr_mode mode;

    /* pointer to the msix vectors to be allocated later */
    struct msix_entry msix_entries[NFP_NUM_MSI_VECTORS];
};

#define PCI_VENDOR_ID_NETRONOME     0x19ee
#define PCI_DEVICE_NFP6000_PF_NIC   0x6000
#define PCI_DEVICE_NFP6000_VF_NIC   0x6003

#define RTE_PCI_DEV_ID_DECL_NETRO(vend, dev) {PCI_DEVICE(vend, dev)},

int pf_support = 1;
struct platform_device *dev_cpp = NULL;
struct nfp_cpp *cpp;

/* PCI device id table */
static struct pci_device_id nfp_uio_pci_ids[] = {
RTE_PCI_DEV_ID_DECL_NETRO(PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP6000_PF_NIC)
RTE_PCI_DEV_ID_DECL_NETRO(PCI_VENDOR_ID_NETRONOME, PCI_DEVICE_NFP6000_VF_NIC)
{ 0, },
};

MODULE_DEVICE_TABLE(pci, nfp_uio_pci_ids);

static inline struct
nfp_uio_pci_dev *nfp_uio_get_uio_pci_dev(struct uio_info *info)
{
    return container_of(info, struct nfp_uio_pci_dev, info);
}


static inline int pci_lock(struct pci_dev *pdev)
{
    /* Some function names changes between 3.2.0 and 3.3.0... */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
    pci_block_user_cfg_access(pdev);
    return 1;
#else
    return pci_cfg_access_trylock(pdev);
#endif
}

static inline void pci_unlock(struct pci_dev *pdev)
{
    /* Some function names changes between 3.2.0 and 3.3.0... */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
    pci_unblock_user_cfg_access(pdev);
#else
    pci_cfg_access_unlock(pdev);
#endif
}

#ifdef CONFIG_PCI_MSI
/*
 * It masks the msi on/off of generating MSI messages.
 */
static int nfp_uio_msi_mask_irq(struct msi_desc *desc, int32_t state)
{
    uint32_t mask_bits = desc->masked;
    uint32_t val;

    if (state != 0)
        mask_bits |= (1 << desc->msi_attrib.entry_nr);
    else
        mask_bits &= ~(1 << desc->msi_attrib.entry_nr);

    if (mask_bits != desc->masked) {
        pci_write_config_word(desc->dev, desc->mask_pos, mask_bits);
        /* Doing same thing as nfp_uio_msix_mask_irq. barrier? */
        pci_read_config_dword(desc->dev, desc->mask_pos, &val);
        desc->masked = mask_bits;
    }

    return 0;
}

/*
 * It masks the msix on/off of generating MSI-X messages.
 */
static int nfp_uio_msix_mask_irq(struct msi_desc *desc, int32_t state)
{
    uint32_t mask_bits = desc->masked;
    unsigned offset = desc->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE +
                      PCI_MSIX_ENTRY_VECTOR_CTRL;

    if (state != 0)
        mask_bits &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;
    else
        mask_bits |= PCI_MSIX_ENTRY_CTRL_MASKBIT;

    if (mask_bits != desc->masked) {
        writel(mask_bits, desc->mask_base + offset);
        readl(desc->mask_base);
        desc->masked = mask_bits;
    }

    return 0;
}
#endif /* CONFIG_PCI_MSI */

/**
 * This function sets/clears the masks for generating LSC interrupts.
 *
 * @param info
 *   The pointer to struct uio_info.
 * @param on
 *   The on/off flag of masking LSC.
 * @return
 *   -On success, zero value.
 *   -On failure, a negative value.
 */
static int nfp_uio_set_interrupt_mask(struct nfp_uio_pci_dev *udev,
                                      int32_t state)
{
    struct pci_dev *pdev = udev->pdev;

    /* TODO: Should we change this based on if the firmware advertises
       NFP_NET_CFG_CTRL_MSIXAUTO? */

    if (udev->mode == NFP_UIO_LEGACY_INTR_MODE) {
        uint32_t status;
        uint16_t old, new;

        pci_read_config_dword(pdev, PCI_COMMAND, &status);
        old = status;
        if (state != 0)
            new = old & (~PCI_COMMAND_INTX_DISABLE);
        else
            new = old | PCI_COMMAND_INTX_DISABLE;

        if (old != new)
            pci_write_config_word(pdev, PCI_COMMAND, new);
#ifdef CONFIG_PCI_MSI
    } else if (udev->mode == NFP_UIO_MSIX_INTR_MODE) {
        struct msi_desc *desc;
        list_for_each_entry(desc, &pdev->msi_list, list) {
            nfp_uio_msix_mask_irq(desc, state);
        }
    } else if (udev->mode == NFP_UIO_MSI_INTR_MODE) {
        struct msi_desc *desc;
        list_for_each_entry(desc, &pdev->msi_list, list) {
            nfp_uio_msi_mask_irq(desc, state);
        }
#endif
    }

    return 0;
}

/**
 * This is the irqcontrol callback to be registered to uio_info.
 * It can be used to disable/enable interrupt from user space processes.
 *
 * @param info
 *  pointer to uio_info.
 * @param irq_state
 *  state value. 1 to enable interrupt, 0 to disable interrupt.
 *
 * @return
 *  - On success, 0.
 *  - On failure, a negative value.
 */
static int nfp_uio_pci_irqcontrol(struct uio_info *info, s32 irq_state)
{
    unsigned long flags;
    struct nfp_uio_pci_dev *udev = nfp_uio_get_uio_pci_dev(info);
    struct pci_dev *pdev = udev->pdev;

    spin_lock_irqsave(&udev->lock, flags);
    if (!pci_lock(pdev)) {
        spin_unlock_irqrestore(&udev->lock, flags);
        return -1;
    }

    nfp_uio_set_interrupt_mask(udev, irq_state);

    pci_unlock(pdev);
    spin_unlock_irqrestore(&udev->lock, flags);
    return 0;
}

/**
 * This is interrupt handler which will check if the interrupt is for the right
   device. 
 */
static irqreturn_t
nfp_uio_pci_irqhandler(int irq, struct uio_info *info)
{
    irqreturn_t ret = IRQ_NONE;
    unsigned long flags;
    struct nfp_uio_pci_dev *udev = nfp_uio_get_uio_pci_dev(info);
    struct pci_dev *pdev = udev->pdev;
    uint32_t cmd_status_dword;
    uint16_t status;

    spin_lock_irqsave(&udev->lock, flags);
    /* block userspace PCI config reads/writes */
    if (!pci_lock(pdev))
        goto spin_unlock;

    /* for legacy mode, interrupt maybe shared */
    if (udev->mode == NFP_UIO_LEGACY_INTR_MODE) {
        pci_read_config_dword(pdev, PCI_COMMAND, &cmd_status_dword);
        status = cmd_status_dword >> 16;
        /* interrupt is not ours, goes to out */
        if (!(status & PCI_STATUS_INTERRUPT))
            goto done;
    }

    nfp_uio_set_interrupt_mask(udev, 0);
    ret = IRQ_HANDLED;
done:
    /* unblock userspace PCI config reads/writes */
    pci_unlock(pdev);
spin_unlock:
    spin_unlock_irqrestore(&udev->lock, flags);
    dev_info(&pdev->dev, "irq 0x%x %s\n", irq,
             (ret == IRQ_HANDLED) ? "handled" : "not handled");

    return ret;
}

/* Remap pci resources described by bar #pci_bar in uio resource n. */
static int nfp_uio_pci_setup_iomem(struct pci_dev *dev, struct uio_info *info,
                                   int n, int pci_bar, const char *name)
{
    unsigned long addr, len;
    void *internal_addr;

    if (sizeof(info->mem) / sizeof(info->mem[0]) <= n)
        return -EINVAL;

    addr = pci_resource_start(dev, pci_bar);
    len = pci_resource_len(dev, pci_bar);
    if (addr == 0 || len == 0)
        return -1;
    internal_addr = ioremap(addr, len);
    if (internal_addr == NULL)
        return -1;
    info->mem[n].name = name;
    info->mem[n].addr = addr;
    info->mem[n].internal_addr = internal_addr;
    info->mem[n].size = len;
    info->mem[n].memtype = UIO_MEM_PHYS;
    return 0;
}

/* Get pci port io resources described by bar #pci_bar in uio resource n. */
static int nfp_uio_pci_setup_ioport(struct pci_dev *dev, struct uio_info *info,
                                    int n, int pci_bar, const char *name)
{
    unsigned long addr, len;

    if (sizeof(info->port) / sizeof(info->port[0]) <= n)
        return -EINVAL;

    addr = pci_resource_start(dev, pci_bar);
    len = pci_resource_len(dev, pci_bar);
    if (addr == 0 || len == 0)
        return -1;

    info->port[n].name = name;
    info->port[n].start = addr;
    info->port[n].size = len;
    info->port[n].porttype = UIO_PORT_X86;

    return 0;
}

/* Unmap previously ioremap'd resources */
static void nfp_uio_pci_release_iomem(struct uio_info *info)
{
    int i;

    for (i = 0; i < MAX_UIO_MAPS; i++) {
        if (info->mem[i].internal_addr)
            iounmap(info->mem[i].internal_addr);
    }
}

static int nfp_uio_setup_bars(struct pci_dev *dev, struct uio_info *info)
{
    int i, iom, iop, ret;
    unsigned long flags;
    static const char *bar_names[PCI_STD_RESOURCE_END + 1]  = {
        "BAR0",
        "BAR1",
        "BAR2",
        "BAR3",
        "BAR4",
        "BAR5",
    };

    iom = 0;
    iop = 0;

    for (i = 0; i != sizeof(bar_names) / sizeof(bar_names[0]); i++) {
        if (pci_resource_len(dev, i) == 0 || pci_resource_start(dev, i) == 0)
            continue;

        flags = pci_resource_flags(dev, i);
        if (flags & IORESOURCE_MEM) {
            ret = nfp_uio_pci_setup_iomem(dev, info, iom, i, bar_names[i]);
            if (ret != 0)
                return ret;
            iom++;
        } else if (flags & IORESOURCE_IO) {
            ret = nfp_uio_pci_setup_ioport(dev, info, iop, i, bar_names[i]);
            if (ret != 0)
                return ret;
            iop++;
        }
}

    return (iom != 0) ? ret : -ENOENT;
}

/* Configuring interrupt. First try MSI-X, then MSI. */
static void init_interrupt(struct nfp_uio_pci_dev *udev)
{
    int vector;

    for (vector = 0; vector < NFP_NUM_MSI_VECTORS; vector++)
        udev->msix_entries[vector].entry = vector;

    if (pci_enable_msix(udev->pdev, udev->msix_entries, NFP_NUM_MSI_VECTORS)
        == 0) {
        udev->mode = NFP_UIO_MSIX_INTR_MODE;
        udev->info.irq_flags = 0;
        udev->info.irq = udev->msix_entries[0].vector;
        dev_info(&udev->pdev->dev, "%s configured with MSI-X\n",
                 udev->info.name);
        return;
    }

    if (pci_enable_msi(udev->pdev) == 0) {
        udev->mode = NFP_UIO_MSI_INTR_MODE;
        udev->info.irq_flags = 0;
        udev->info.irq = udev->pdev->irq;
        dev_info(&udev->pdev->dev, "%s configured with MSI\n", udev->info.name);
        return;
    }

    /* Legacy interrupt */
    udev->mode = NFP_UIO_LEGACY_INTR_MODE;
    udev->info.irq_flags = IRQF_SHARED;
    udev->info.irq = udev->pdev->irq;
    dev_info(&udev->pdev->dev, "%s configuring Legacy interrupt\n",
             udev->info.name);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
static int __devinit
#else
static int
#endif
nfp_uio_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct nfp_uio_pci_dev *udev;
    void *map_addr;
    dma_addr_t map_dma_addr;
    int err;

    udev = kzalloc(sizeof(*udev), GFP_KERNEL);
    if (!udev)
        return -ENOMEM;
    /* enable device: ask low-level code to enable I/O and memory */
    if (pci_enable_device(dev)) {
        dev_err(&dev->dev, "Cannot enable PCI device\n");
        goto fail_free;
    }

    /* reserve device's PCI memory regions for use by this module */
    if (pci_request_regions(dev, "nfp_uio")) {
        dev_err(&dev->dev, "Cannot request regions\n");
        goto fail_disable;
    }

    /* enable bus mastering on the device */
    pci_set_master(dev);

    /* remap IO memory */
    if (nfp_uio_setup_bars(dev, &udev->info))
        goto fail_release_iomem;

    /* set 64-bit DMA mask */
    if (pci_set_dma_mask(dev,  DMA_BIT_MASK(40))) {
        dev_err(&dev->dev, "Cannot set DMA mask\n");
        goto fail_release_iomem;
    } else if (pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(40))) {
        dev_err(&dev->dev, "Cannot set consistent DMA mask\n");
        goto fail_release_iomem;
    }

    if (pf_support) {
        cpp = nfp_cpp_from_nfp6000_pcie(dev, -1);

        if (IS_ERR_OR_NULL(cpp)) {
            err = PTR_ERR(cpp);
            if (err >= 0)
                err = -ENOMEM;
            goto fail_release_iomem;
        }

        dev_cpp = nfp_platform_device_register(cpp, NFP_DEV_CPP_TYPE);
        if (!dev_cpp) {
            dev_err(&dev->dev, "Failed to enable user space access");
            goto fail_nfp_cpp;
        }
    }

    /* fill uio infos */
    udev->info.name = "Netronome NFP UIO";
    udev->info.version = "0.1";
    udev->info.handler = nfp_uio_pci_irqhandler;
    udev->info.irqcontrol = nfp_uio_pci_irqcontrol;
    udev->info.priv = udev;
    udev->pdev = dev;
    udev->mode = 0; /* set the default value for interrupt mode */
    spin_lock_init(&udev->lock);
    init_interrupt(udev);
    pci_set_drvdata(dev, &udev->info);
    nfp_uio_pci_irqcontrol(&udev->info, 0);

    /* register uio driver */
    if (uio_register_device(&dev->dev, &udev->info))
        goto fail_uio_reg;

    dev_info(&dev->dev, "uio device registered with irq %lx\n", udev->info.irq);

    /* (NFDH-100) When binding drivers to devices, some old kernels do not link
       devices to iommu identity mapping if iommu=pt is used. This is not a
       problem if the driver does later some call to the DMA API because the
       mapping can be done then. But DPDK apps do not use that DMA API at all.
       Doing a harmless dma mapping for attaching the device to the iomm
       identity mapping */

    map_addr = dma_zalloc_coherent(&dev->dev, 1024, &map_dma_addr, GFP_KERNEL);

    printk("nfp_uio: mapping 1K dma=%#llx host=%p\n",
           (unsigned long long)map_dma_addr, map_addr);

    dma_free_coherent(&dev->dev, 1024, map_addr, map_dma_addr);

    printk("nfp_uio: unmapping 1K dma=%#llx host=%p\n",
           (unsigned long long)map_dma_addr, map_addr);

    return 0;

fail_uio_reg:
    if (pf_support)
        nfp_platform_device_unregister(dev_cpp);
fail_nfp_cpp:
    if (pf_support)
        nfp_cpp_free(cpp);
fail_release_iomem:
    nfp_uio_pci_release_iomem(&udev->info);
    if (udev->mode == NFP_UIO_MSIX_INTR_MODE)
        pci_disable_msix(udev->pdev);
    if (udev->mode == NFP_UIO_MSI_INTR_MODE)
        pci_disable_msi(udev->pdev);
    pci_release_regions(dev);
fail_disable:
    pci_disable_device(dev);
fail_free:
    kfree(udev);

    return -ENODEV;
}

static void nfp_uio_pci_remove(struct pci_dev *dev)
{
    struct uio_info *info = pci_get_drvdata(dev);

    BUG_ON(!info);
    BUG_ON(!info->priv);

    uio_unregister_device(info);
    nfp_uio_pci_release_iomem(info);

    if (((struct nfp_uio_pci_dev *)info->priv)->mode == NFP_UIO_MSIX_INTR_MODE)
        pci_disable_msix(dev);
    
    if (((struct nfp_uio_pci_dev *)info->priv)->mode == NFP_UIO_MSI_INTR_MODE)
        pci_disable_msi(dev);

    if (pf_support) {
        nfp_platform_device_unregister(dev_cpp);
        nfp_cpp_free(cpp);
    }

    pci_release_regions(dev);
    pci_disable_device(dev);
    pci_set_drvdata(dev, NULL);
    kfree(info);
}

static struct pci_driver nfp_uio_pci_driver = {
    .name = "nfp_uio",
    .id_table = nfp_uio_pci_ids,
    .probe = nfp_uio_pci_probe,
    .remove = nfp_uio_pci_remove,
};

static int __init nfp_uio_pci_init_module(void)
{
    int err;

    if (find_module("nfp")) {
        pr_info("nfp_uio: nfp module detected. Just VF support\n");
        pf_support = 0;
    }

    if (find_module("nfp_net")) {
        pr_info("nfp_uio: nfp_net module detected. Just VF support\n");
        pf_support = 0;
    }

    pr_info("nfp_uio: NFP UIO driver PF/VF, Copyright (C) 2014-2015 Netronome"
            " Systems\n");

   
    if (pf_support) {
        err = nfp_cppcore_init();
        if (err < 0)
            goto fail_cppcore_init;

        err = nfp_dev_cpp_init();
        if (err < 0)
            goto fail_dev_cpp_init;
    }
    err = pci_register_driver(&nfp_uio_pci_driver);
    if (err < 0)
        goto fail_pci_init;

    return err;

fail_pci_init:
    if (pf_support)
        nfp_dev_cpp_exit();
fail_dev_cpp_init:
    if (pf_support)
        nfp_cppcore_exit();
fail_cppcore_init:
    return err;
}

static void __exit nfp_uio_pci_exit_module(void)
{
    pci_unregister_driver(&nfp_uio_pci_driver);
    if (pf_support)
        nfp_dev_cpp_exit();
    if (pf_support)
        nfp_cppcore_exit();
}

module_init(nfp_uio_pci_init_module);
module_exit(nfp_uio_pci_exit_module);

MODULE_DESCRIPTION("UIO driver for Netronome NFP PCI cards");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netronome Systems <support@netronome.com>");
