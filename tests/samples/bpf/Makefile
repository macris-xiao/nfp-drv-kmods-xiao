LLVM_VERSION ?= -4.0
LLVM := $(shell clang$(LLVM_VERSION) --version)

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

Q ?= @

%.o: %.c
	@echo "\tLLVM BUILD $@"
	$(Q) clang$(LLVM_VERSION) $(INCLUDE_DIRS) -O2 -emit-llvm -c $< -W -Wall -o $(patsubst %.o,%.llvm,$@)
	$(Q) llc$(LLVM_VERSION) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.llvm,$@)
	$(Q) rm $(patsubst %.o,%.llvm,$@)

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
