#####################################
# Work out where the kernel source is

ifeq (,$(KVER))
KVER=$(shell uname -r)
endif

KERNEL_SEARCH_PATH := \
	/lib/modules/$(KVER)/build \
	/lib/modules/$(KVER)/source \
	/usr/src/linux-$(KVER) \
	/usr/src/linux-$($(KVER) | sed 's/-.*//') \
	/usr/src/kernel-headers-$(KVER) \
	/usr/src/kernel-source-$(KVER) \
	/usr/src/linux-$($(KVER) | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/') \
	/usr/src/linux

# prune list to those containing a configured kernel source tree
test_dir = $(shell [ -e $(dir)/include/config ] && echo $(dir))
KERNEL_SEARCH_PATH := $(foreach dir, $(KERNEL_SEARCH_PATH), $(test_dir))

# Use first one
ifeq (,$(KSRC))
  KSRC := $(firstword $(KERNEL_SEARCH_PATH))
endif

ifeq (,$(KSRC))
  $(error Could not find kernel source)
endif


EXTRA_CFLAGS += $(CFLAGS_EXTRA)


###########################################################################
# Build rules
build: clean
	$(MAKE) ccflags-y:="$(CFLAGS_EXTRA)" -C $(KSRC) M=`pwd` modules

noisy: clean
	$(MAKE) ccflags-y:="$(CFLAGS_EXTRA)" -C $(KSRC) M=`pwd` V=1 modules

coccicheck: clean
	$(MAKE) ccflags-y:="$(CFLAGS_EXTRA)" -C $(KSRC) M=`pwd` coccicheck MODE=report

clean:
# Pass makecmd to disable some config checks
	$(MAKE) -C $(KSRC) M=`pwd` makecmd=clean clean

install: build
	$(MAKE) -C $(KSRC) M=`pwd` modules_install



