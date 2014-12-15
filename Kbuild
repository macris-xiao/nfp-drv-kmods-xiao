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
ifeq ($(CONFIG_XEN_UNPRIVILEGED_GUEST),y)
CONFIG_NFE ?= n
else
ifeq ($(KBUILD_EXTMOD),)
CONFIG_NFE = y
else
CONFIG_NFE ?= m
endif
endif

# un-comment for debug symbols
# override EXTRA_CFLAGS += -g3

ifeq ($(CONFIG_ARCH_NFP),)
# FIXME: Disable vPCI MSI/X support for now,
# since it is currently depenent on the nfp3200 implementation
# override EXTRA_CFLAGS += -DCONFIG_NFE_MSIX
endif

ifneq ($(makecmd),clean)
ifneq ($(CONFIG_PCI),y)
  $(error NFE: The PCI subsystem (CONFIG_PCI) must be enabled)
endif

ifneq ($(CONFIG_NFE),n)
  ifeq ($(CONFIG_X86),y)
    ifneq ($(CONFIG_PCI_MSI),y)
      $(error NFE: MSI interrupts (CONFIG_PCI_MSI) must be enabled)
    endif
    ifneq ($(CONFIG_X86_LOCAL_APIC),y)
      $(error NFE: the local APIC (CONFIG_X86_LOCAL_APIC) must be enabled, to recieve MSI interrupts)
    endif
  endif
  ifneq ($(CONFIG_FW_LOADER),y)
    $(warning NFE: The firmware loader (CONFIG_FW_LOADER) should be enabled)
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

obj-$(CONFIG_NFE)      += nfp.o

## define some compat defines which we can't work out with the
## pre-processor alone

ifeq ($(shell [ "$(VERSION).$(PATCHLEVEL)" = "2.6" -a "$(SUBLEVEL)" -lt 21 ] && echo devm_ioremap),devm_ioremap)
# < 2.6.21 does not have devm_ioremap_nocache() and devm_iounmap()
# but centos 5.x 2.6.18 kernels do
ifeq (,$(findstring el5,$(KERNELRELEASE))) # no el5 in kernelrelease
override EXTRA_CFLAGS += -DNFE_COMPAT_NEED_DEVM_IOREMAP
endif
endif

ifeq ($(findstring .el6.,$(KERNELRELEASE)),.el6.)
override EXTRA_CFLAGS += -DNFE_RHEL6
endif


nfp-objs := nfpcore/nfp3200_pcie.o \
	    nfpcore/nfp6000_pcie.o \
	    nfpcore/nfp_ca.o \
	    nfpcore/nfp_cppcore.o \
	    nfpcore/nfp_cpplib.o \
	    nfpcore/nfp_device.o \
	    nfpcore/nfp_em_manager.o \
	    nfpcore/nfp_resource.o \
	    nfpcore/nfp6000_nbi.o \
	    nfpcore/nfp_gpio.o \
	    nfpcore/nfp_i2c.o \
	    nfpcore/i2c.o \
	    nfpcore/i2c_gpio.o \
	    nfpcore/nfp_nbi_phymod.o \
	    nfpcore/crc32.o \
	    nfpcore/nfp_mip.o \
	    nfpcore/nfp_hwinfo.o \
	    nfpcore/nfp_rtsym.o \
	    nfpcore/nfp_dev_cpp.o \
	    nfpcore/nfp_mon_err.o \
	    nfpcore/nfp_net_null.o \
	    nfpcore/nfp_net_vnic.o \
	    nfp_main.o

ifneq ($(CONFIG_ARCH_NFP),)
nfp-objs += nfpcore/nfp3200_plat.o
endif

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
nfp_src_ver  := $(shell hg -R $(nfp_src_dir)/.. id -ni)
endif

clean-files := $(obj)/nfe_build_info.h
$(obj)/nfe_build_info.h: FORCE
	@echo "/* Automatically generated file */" > $@
	@echo "#define NFP_SRC_VERSION \"$(nfp_src_ver)\"" >> $@
	@echo "#define NFP_BUILD_USER_ID \"$(shell id -u -n)\"" >> $@
	@echo "#define NFP_BUILD_USER \"$(shell getent passwd `id -u -n` | cut -d ':' -f 5 | cut -d ',' -f 1)\"" >> $@
	@echo "#define NFP_BUILD_HOST \"$(shell hostname)\"" >> $@
	@echo "#define NFP_BUILD_PATH \"$(obj)\"" >> $@
	@echo "#define NFP_SRC_PATH \"$(nfp_src_dir)\"" >> $@

$(obj)/nfp_main.o: $(obj)/nfe_build_info.h
