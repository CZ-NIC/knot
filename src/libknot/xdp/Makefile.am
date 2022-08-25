# Useful commands:
#   make filter
#   ip link show $eth
#   sudo ip link set dev $eth xdp off
#   sudo ip link set dev $eth xdp obj ./bpf-kernel.o
#
# Built using LLVM/CLANG 14.
#
# When updating check using `llvm-objdump -h bpf-kernel.o` if .BTF and .BTF.ext
# sections are present.

EXTRA_DIST = bpf-kernel-obj.c bpf-kernel.c

.PHONY: filter

filter:
	rm -f bpf-kernel.o bpf-kernel-obj.c
	clang -target bpf -Wall -O2 -g -DNDEBUG -c -o bpf-kernel.o -I/usr/include/x86_64-linux-gnu -include ../../config.h bpf-kernel.c
	llvm-strip -S bpf-kernel.o
	xxd -i bpf-kernel.o > bpf-kernel-obj.c
