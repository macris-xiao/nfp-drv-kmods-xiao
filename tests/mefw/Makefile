ifeq ($(FLOWENV_PATH),)
$(error Please set FLOWENV_PATH)
endif

# Set those to what your card is
CHIP ?= nfp-4xxx-b0
AMDA ?= hydrogen

NFCC := nfcc
CFLAGS := -W3 -chip $(CHIP) -I$(FLOWENV_PATH)/me/include -I$(FLOWENV_PATH)/me/lib
CLIBS :=  $(FLOWENV_PATH)/me/lib/nfp/libnfp.c

NFLD := nfld
LDFLAGS := -res.i24.emem.base 0x00008000 -chip $(CHIP)
TARGET_MES := mei0.me0

NFCA := nfp-nffw2ca
CAFLAGS := --amda=$(AMDA)

# Build firmwares for RT-SYM testing, number denotes the count of symbols
# to include in the firmware
RTSYM_FILES := rts_0.list rts_1.list rts_2.list rts_3.list rts_17.list \
	rts_100.list

# Build the firmwares with MIP and RT-SYM but also one without MIP or
# a specific version of it
FWS = $(patsubst %.list,rm_%.nffw,${RTSYM_FILES}) \
	rts_100.nffw rm1_rts_100.nffw rm2_rts_100.nffw

CAS = $(patsubst %.nffw,%.ca,${FWS})

all: $(FWS) $(CAS) clean

%.nffw: %.list
	$(NFLD) $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm_%.nffw: %.list
	$(NFLD) -rtsyms -mip $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm1_%.nffw: %.list
	$(NFLD) -rtsyms -mip_v1 $(LDFLAGS) -o $@ -u $(TARGET_MES) $<
rm2_%.nffw: %.list
	$(NFLD) -rtsyms -mip_v2 $(LDFLAGS) -o $@ -u $(TARGET_MES) $<

%.ca: %.nffw
	$(NFCA) $(CAFLAGS) $<

# This rule will generate different count of RT-SYMS by setting a define
# and using the single C source as a basis
rts_%.list: rts.c
	$(NFCC) $< $(CFLAGS) $(CLIBS) -o $@ \
	-D NUM_SYMS=$(subst .list,,$(subst rts_,,$@))

clean:
	rm -f *.list *.obj *.db *.trace

distclean: clean
	rm -f *.nffw *.ca

.PHONY: all clean distclean
