#!/usr/bin/env bash

set -e
set -x

[ ! -d "mujs" ] && unzip mujs.zip

mkdir -p mujs-build
cd mujs-build
cmake ../mujs
make
cd ..
rm -fr mujs
mv mujs-build/mujs .
rm -fr mujs-build
cd wrapper_dir
make all
cd ..
mv wrapper_dir/wrapper .
