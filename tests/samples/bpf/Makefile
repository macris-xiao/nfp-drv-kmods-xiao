LLVM_VERSION ?= 13
LLVM := $(shell clang-$(LLVM_VERSION) --version)
CLANG_FLAGS ?= -O2 -W -Wall \
	-Wno-compare-distinct-pointer-types
CLANG_DIRS ?= /lib/clang/$(LLVM_VERSION)/include
KERNEL_HEADERS ?= $(KSRC)/usr/include

# Some OS use the llc command with a version number and some use it without
# If llc-$(LLVM_VERSION) is in the PATH then use that path, otherwise just
# use llc
llvm_13_path = $(shell which llc-$(LLVM_VERSION))
ifeq ($(llvm_13_path), "/usr/bin/llc-13")
    llc_command = llc-$(LLVM_VERSION)
else
    llc_command = llc
endif

# Exclude testcases requiring specific eBPF CPU versions initially. They do not
# always compile on old LLVM toolchain. Include them depending on probe results.
ALL_SRCS = $(wildcard *.c *.S)
SRCS = $(filter-out $(SRCS_LLVM_CPU_V3), $(ALL_SRCS))
LLVM_SUPPORT_CPU_V3 = $(shell echo "int main () { return 0; }" | \
			clang-$(LLVM_VERSION) -target bpf -mcpu=v3 -E - 2>&1 | \
			grep "main")
ifneq ($(LLVM_SUPPORT_CPU_V3),)
SRCS += $(SRCS_LLVM_CPU_V3)
CFLAGS += -mcpu=v3
endif

OBJS=$(patsubst %.c,%.o,$(SRCS)) $(patsubst %.S,%.o,$(SRCS))

Q ?= @

%.o: %.c
	@echo "\tLLVM CC $@"
	$(Q) clang-$(LLVM_VERSION) $(INCLUDE_DIRS) -I$(KERNEL_HEADERS) -I$(CLANG_DIRS) \
		-emit-llvm -c $< $(CLANG_FLAGS) -o $(patsubst %.o,%.llvm,$@)
	$(Q) $(llc_command) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.llvm,$@)
	$(Q) rm $(patsubst %.o,%.llvm,$@)

%.o: %.S
	@echo "\tLLVM ASM $@"
	$(Q) clang-$(LLVM_VERSION) -target bpf $(INCLUDE_DIRS) $(CLANG_FLAGS) -c $< -o $@

ifeq ($(LLVM),)
all:
	$(warning Install LLVM to compile BPF sources)
else
all: $(OBJS)
endif

clean:
	rm -f *.llvm

distclean: clean
	rm -f *.o

.PHONY: all clean
