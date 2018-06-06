include ../bpf/Makefile

CLANG_FLAGS += -Wno-unused-function

xdp_performance:
ifeq ($(wildcard 0x*.c),)
	./generate_objects.py
endif
	$(MAKE) all

.PHONY: xdp_performance
.DEFAULT_GOAL := xdp_performance
