##
##  Copyright (C) 2008-2010 Netronome Systems, Inc.  All rights reserved.
##
##  @file kernel/Kbuild
##
##  This file provides Linux kernel build rules, for executing within the
##  Kbuild environment.
##

## Define our own config variables.
## A kernel Kconfig file may define these variables one day.
CONFIG_MFD_NFP ?= m

## Set to n to disable all EXPORT_SYMBOL() macros
CONFIG_MFD_NFP_EXPORT ?= y

# un-comment for debug symbols
# override EXTRA_CFLAGS += -g3

ifeq ($(CONFIG_MFD_NFP_EXPORT),y)
override EXTRA_CFLAGS += -DCONFIG_MFD_NFP_EXPORT=1
endif

ifneq ($(makecmd),clean)
ifneq ($(CONFIG_PCI),y)
  $(error MFD_NFP: The PCI subsystem (CONFIG_PCI) must be enabled)
endif

# FIXME: This should be encoded in Kconfig
ifneq ($(CONFIG_MDF_NFP),n)
  ifeq ($(CONFIG_X86),y)
    ifneq ($(CONFIG_PCI_MSI),y)
      $(error MFD_NFP: MSI interrupts (CONFIG_PCI_MSI) must be enabled)
    endif
    ifneq ($(CONFIG_X86_LOCAL_APIC),y)
      $(error MFD_NFP: the local APIC (CONFIG_X86_LOCAL_APIC) must be enabled, to recieve MSI interrupts)
    endif
  endif
  ifneq ($(CONFIG_FW_LOADER),y)
    $(warning MDF_NFP: The firmware loader (CONFIG_FW_LOADER) should be enabled)
  endif
endif
endif

override EXTRA_CFLAGS += -DCONFIG_NFP_A0_WORKAROUND -DCONFIG_NFP_A1_WORKAROUND
override EXTRA_CFLAGS += -DDEBUG
override EXTRA_CFLAGS += -Werror
ifeq ($(VERSION).$(PATCHLEVEL).$(SUBLEVEL),2.6.28)
override EXTRA_CFLAGS += -I$(src)
endif
override EXTRA_CFLAGS += -I$(src)/include

obj-$(CONFIG_MFD_NFP) += nfp.o

nfp-objs := nfpcore/nfp3200_pcie.o \
	    nfpcore/nfp3200_plat.o \
	    nfpcore/nfp6000_pcie.o \
	    nfpcore/nfp6000_nbi.o \
	    nfpcore/crc32.o \
	    nfpcore/i2c.o \
	    nfpcore/i2c_gpio.o \
	    nfpcore/nfp_ca.o \
	    nfpcore/nfp_cppcore.o \
	    nfpcore/nfp_cpplib.o \
	    nfpcore/nfp_dev_cpp.o \
	    nfpcore/nfp_device.o \
	    nfpcore/nfp_em_manager.o \
	    nfpcore/nfp_gpio.o \
	    nfpcore/nfp_hwinfo.o \
	    nfpcore/nfp_i2c.o \
	    nfpcore/nfp_mip.o \
	    nfpcore/nfp_mon_err.o \
	    nfpcore/nfp_nbi_phymod.o \
	    nfpcore/nfp_net_null.o \
	    nfpcore/nfp_net_vnic.o \
	    nfpcore/nfp_nffw.o \
	    nfpcore/nfp_platform.o \
	    nfpcore/nfp_resource.o \
	    nfpcore/nfp_rtsym.o \
	    nfpcore/nfp_spi.o \
	    nfp_main.o


####################
# Build information
####################

# Determine the NFP driver's source directory.
nfp_src_dir := $(dir $(realpath $(src)/nfp_main.c))
ifeq ($(nfp_src_dir),)
nfp_src_dir := $(dir $(shell readlink $(src)/nfp_main.c))
endif
ifeq ($(nfp_src_dir),)
nfp_src_dir := .
endif

# Get the source control revisions.
ifeq ($(nfp_src_ver),)
nfp_src_ver  := $(shell (cd $(nfp_src_dir); git rev-parse --short HEAD))
endif

clean-files := $(obj)/nfp_build_info.h
$(obj)/nfp_build_info.h: FORCE
	@echo "/* Automatically generated file */" > $@
	@echo "#define NFP_SRC_VERSION \"$(nfp_src_ver)\"" >> $@
	@echo "#define NFP_BUILD_USER_ID \"$(shell id -u -n)\"" >> $@
	@echo "#define NFP_BUILD_USER \"$(shell getent passwd `id -u -n` | cut -d ':' -f 5 | cut -d ',' -f 1)\"" >> $@
	@echo "#define NFP_BUILD_HOST \"$(shell hostname)\"" >> $@
	@echo "#define NFP_BUILD_PATH \"$(obj)\"" >> $@
	@echo "#define NFP_SRC_PATH \"$(nfp_src_dir)\"" >> $@

$(obj)/nfp_main.o: $(obj)/nfp_build_info.h
