include ../bpf/Makefile

CLANG_FLAGS += -Wno-unused-function

all: $(OBJS)
ifeq ($(wildcard 0x*.c),)
	./generate_objects.py
	$(MAKE)
endif
