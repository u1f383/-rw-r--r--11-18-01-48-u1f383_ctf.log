#!/bin/bash

gdb \
    -ex "file vmlinux"\
    -ex "tr"\
    -ex "add-symbol-file babydriver.ko 0xffffffffc0000000"\
