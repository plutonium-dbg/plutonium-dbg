#!/bin/sh

set -e
cd linux
make clean
make defconfig
make -j32 bzImage
