#!/bin/bash

make -C src

cd rootfs

find . -print0 | cpio --null -ov --format=newc > ../local.cpio

cd .. && exec ./start.sh
