obj: sr6_bfd.c
	clang -O2 -emit-llvm -c sr6_bfd.c -o - | llc -march=bpf -filetype=obj -o sr6_bfd.o

frr: frr.cc
	g++ -std=c++11 -I/usr/include/bcc/ -Iinclude/ fmt/format.cc fmt/posix.cc /usr/lib/libbcc.so frr.cc -o frr

all: obj frr
