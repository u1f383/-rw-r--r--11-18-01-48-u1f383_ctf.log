PWD= $(shell pwd)
SRCS = $(wildcard *.c)
EXPS = $(SRCS:.c=)
DEST = $(PWD)/../rootfs/tmp

all: $(EXPS)

$(EXPS):
	musl-gcc -o $(DEST)/$@ -static -masm=intel $@.c
