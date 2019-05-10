LIBBPF_PATH ?=

SRCS=$(wildcard *.c *.S)
OBJS=$(patsubst %.c,%,$(SRCS))

LIBSRCS=$(wildcard lib/*.c)
LIBOBJS=$(patsubst %.c,%,$(SRCS))

include $(wildcard *.d)

Q ?= @
%: %.c lib/samples.a
	@echo "\tCC $@"
	$(Q) gcc -MMD -W -Wall -Wextra -Wshadow -O2 $< -o $@ \
		lib/samples.a \
		-lpthread -lbpf -lelf -lz \
		-I$(LIBBPF_PATH) -L$(LIBBPF_PATH)

ifeq ($(LIBBPF_PATH),)
all:
	$(warning -- BPF TESTS WARNING --)
	$(warning Please set LIBBPF_PATH to compile user space test programs)
else
all: $(OBJS)
endif

distclean:
	$(Q) rm -f $(OBJS) *.d $(LIBOBJS)

lib/samples.o: lib/samples.c
	@echo "\tCC $@"
	$(Q) gcc -MMD -W -Wall -O2 -c $< -o $@

lib/samples.a: lib/samples.o
	@echo "\tAR $@"
	$(Q) ar rcs lib/samples.a lib/samples.o

.PHONY: all clean
.DEFAULT_GOAL := all
