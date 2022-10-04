# Set those to what your card is
CHIP ?= nfp-4xxx-b0
AMDA ?= hydrogen

NFCC := nfcc
TOOLCHAIN_DIRS ?= /opt/netronome/components/standardlibrary/microc/include
CFLAGS := -W3 -chip $(CHIP)
FWNAME := TEST_FW_12345678

NFLD := nfld

# Some targets needs to be linked using an older version of the toolchain
# Get the version of the toolchain, and if it is old enough just use it, if not
# use the nfld_old binary that is present in newer toolchains
NFLD_OLD := nfld
TOOLCHAIN_VER=$(shell nfld --version | grep Version | grep -Eo "[0-9].[0-9].[0-9].[0-9]")
MAJOR_VER=$(shell echo $(TOOLCHAIN_VER) | cut -d '.' -f 1)
MINOR_VER=$(shell echo $(TOOLCHAIN_VER) | cut -d '.' -f 2)
ifeq ($(MAJOR_VER),6)
ifeq ($(shell expr $(MINOR_VER) \>= 3), 1)
NFLD_OLD := nfld_old
endif
endif

LDFLAGS := -res.i24.emem.base 0x00008000 -chip $(CHIP)
TARGET_MES := mei0.me0

NUM_DUMMY_PORTS ?= 2

# Build firmwares for RT-SYM testing, number denotes the count of symbols
# to include in the firmware
RTSYM_FILES := rts_0.list rts_1.list rts_2.list rts_3.list rts_17.list \
	rts_100.list

# Build the firmwares with MIP and RT-SYM but also one without MIP or
# a specific version of it
FWS = $(patsubst %.list,rm_%_$(CHIP).nffw,${RTSYM_FILES}) \
	rts_100_$(CHIP).nffw rm1_rts_100_$(CHIP).nffw \
	rts_dump_$(CHIP).nffw rts_vals_$(CHIP).nffw dummy_nfd_$(CHIP).nffw

# nfp-3800 cannot use -mip_v2
ifneq ($(CHIP),nfp-38xxc)
FWS += rm2_rts_100_$(CHIP).nffw
endif

all: $(FWS) clean

%_$(CHIP).nffw: %.list
	$(NFLD) $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm_%_$(CHIP).nffw: %.list
	$(NFLD) -rtsyms -mip $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm1_%_$(CHIP).nffw: %.list
	$(NFLD) -rtsyms -mip_v1 $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm2_%_$(CHIP).nffw: %.list
	$(NFLD_OLD) -rtsyms -mip_v2 $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rts_dump_$(CHIP).nffw: rts_17.list abs_rtsym.list
	$(NFLD) -L abs_rtsym.list -rtsyms -fw_name $(FWNAME) -mip $(LDFLAGS) \
	-o $@ -u $(TARGET_MES) $<
rts_vals_$(CHIP).nffw: rts_vals.list abs_rtsym.list
	$(NFLD) -L abs_rtsym.list -rtsyms -fw_name $(FWNAME) -mip $(LDFLAGS) \
	-o $@ -u $(TARGET_MES) $<
dummy_nfd_$(CHIP).nffw: dummy_nfd.list
	$(NFLD) -rtsyms -fw_name $(FWNAME) -mip $(LDFLAGS) \
	-o $@ -u $(TARGET_MES) $<

# This rule will generate different count of RT-SYMS by setting a define
# and using the single C source as a basis
rts_%.list: rts.c
	$(NFCC) $< $(CFLAGS) -I$(TOOLCHAIN_DIRS) -o $@ \
	-D NUM_SYMS=$(subst .list,,$(subst rts_,,$@))

rts_vals.list: rts_vals.c
	$(NFCC) $< $(CFLAGS) -I$(TOOLCHAIN_DIRS) -o $@

abs_rtsym.list: abs_rtsym.uc
	nfas -o $@ --chip $(CHIP) -codeless $<

dummy_nfd.list: dummy_nfd.uc
	nfas $(CFLAGS) -D NUM_DUMMY_PORTS=$(NUM_DUMMY_PORTS) -o $@ $<

clean:
	rm -f *.list *.obj *.db *.trace *.uci *.ucp

distclean: clean
	rm -f *.nffw *.ca

.PHONY: all clean distclean
