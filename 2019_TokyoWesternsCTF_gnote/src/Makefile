PWD = $(shell pwd)
SRCS = $(wildcard *.c)
EXPS = $(SRCS:.c=)
DEST = $(PWD)/../rootfs/tmp

all: $(EXPS)

# $@: targets name
$(EXPS):
	musl-gcc -pthread -o $(DEST)/$@ -static -masm=intel $@.c
