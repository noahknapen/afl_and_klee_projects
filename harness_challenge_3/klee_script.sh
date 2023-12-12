#! /usr/bin/bash

export LLVM_COMPILER=clang
make clean
rm build/emdns.bc
CC=wllvm make
extract-bc emdns
mv emdns.bc build/
cd build/
klee -libc=uclibc -posix-runtime ./emdns.bc -sym-stdin 13
