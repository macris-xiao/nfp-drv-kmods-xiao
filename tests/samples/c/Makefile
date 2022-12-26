LIBBPF_PATH ?=
KERNEL_HEADERS ?= $(KSRC)/usr/include

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%,$(SRCS))
DEPS=$(patsubst %.c,%.d,$(SRCS))

LIBSRCS=$(wildcard lib/*.c)
LIBOBJS=$(patsubst %.c,%.o,$(LIBSRCS)) $(patsubst %.c,%.a,$(LIBSRCS))
LIBDEPS=$(patsubst %.c,%.d,$(LIBSRCS))

include $(wildcard lib/*.d)
include $(wildcard *.d)

Q ?= @

%: %.c lib/samples.a
	@printf "\tCC $@\n"
	$(Q) gcc -MMD -W -Wall -Wextra -Wshadow -O2 -Wl,--as-needed $^ -o $@ \
		-lpthread -lbpf -lelf -lz \
		-I$(LIBBPF_PATH) -I$(KERNEL_HEADERS) -L$(LIBBPF_PATH)

ifeq ($(LIBBPF_PATH),)
all:
	$(warning -- BPF TESTS WARNING --)
	$(warning Please set LIBBPF_PATH to compile user space test programs)
else
all: $(OBJS)
endif

distclean:
	$(Q) rm -f $(OBJS) $(DEPS) $(LIBOBJS) $(LIBDEPS)

lib/samples.o: lib/samples.c
	@printf "\tCC $@\n"
	$(Q) gcc -MMD -W -Wall -O2 -c $< -o $@

lib/samples.a: lib/samples.o
	@printf "\tAR $@\n"
	$(Q) ar rcs $@ $^

.PHONY: all distclean
.DEFAULT_GOAL := all
