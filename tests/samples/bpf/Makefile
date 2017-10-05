LLVM_VERSION ?= -6.0
LLVM := $(shell clang$(LLVM_VERSION) --version)
CLANG_FLAGS ?= -W -Wall \
	-Wno-compare-distinct-pointer-types

SRCS=$(wildcard *.c *.S)
OBJS=$(patsubst %.c,%.o,$(SRCS)) $(patsubst %.S,%.o,$(SRCS))

Q ?= @

%.o: %.c
	@echo "\tLLVM CC $@"
	$(Q) clang$(LLVM_VERSION) $(INCLUDE_DIRS) -O2 -emit-llvm -c $< $(CLANG_FLAGS) -o $(patsubst %.o,%.llvm,$@)
	$(Q) llc$(LLVM_VERSION) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.llvm,$@)
	$(Q) rm $(patsubst %.o,%.llvm,$@)

%.o: %.S
	@echo "\tLLVM MC $@"
	$(Q) llvm-mc$(LLVM_VERSION) -assemble -arch=bpf $< -filetype=obj -o $@

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
