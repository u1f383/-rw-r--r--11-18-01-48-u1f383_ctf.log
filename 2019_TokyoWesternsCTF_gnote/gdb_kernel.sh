#!/bin/bash
# add-auto-load-safe-path: autoload script path
# file: load symbols (?)

gdb \
    -ex "add-auto-load-safe-path $(pwd)" \
    -ex "file vmlinux" \
    -ex 'target remote localhost:1234'
