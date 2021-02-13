#!/bin/bash

tar -xf babydriver.tar
mv rootfs.cpio rootfs.cpio.gz
mkdir rootfs && cp rootfs.cpio.gz rootfs/
cd rootfs
gunzip rootfs.cpio.gz
cpio -i -vd < rootfs.cpio
