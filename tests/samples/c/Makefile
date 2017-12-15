LIBBPF_PATH ?=

SRCS=$(wildcard *.c *.S)
OBJS=$(patsubst %.c,%,$(SRCS))

Q ?= @
%: %.c
	@echo "\tCC $@"
	$(Q) gcc -W -Wall -O2 $< -o $@ -lpthread -lbpf -lelf -static -lz \
		-I$(LIBBPF_PATH) -L$(LIBBPF_PATH)

ifeq ($(LIBBPF_PATH),)
all:
	$(warning -- BPF TESTS WARNING --)
	$(warning Please set LIBBPF_PATH to compile user space test programs)
else
all: $(OBJS)
endif

distclean:
	$(Q) rm -f $(OBJS)

.PHONY: all clean
