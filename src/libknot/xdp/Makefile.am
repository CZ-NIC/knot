# Useful commands:
#   ip link show $eth
#   sudo ip link set dev $eth xdp off
#   sudo ip link set dev $eth xdp obj ./bpf-kernel.o

BUILT_SOURCES = bpf-kernel-obj.c
CLEANFILES = bpf-kernel.ll bpf-kernel.o bpf-kernel-obj.c
EXTRA_DIST = bpf-kernel.c

bpf-kernel.ll: bpf-kernel.c
	clang -S -target bpf -Wall -O2 -emit-llvm -c -DNDEBUG -o $@ -I/usr/include/x86_64-linux-gnu -include ../../config.h $<

bpf-kernel.o: bpf-kernel.ll
	llc -march=bpf -filetype=obj -o $@ $<

bpf-kernel-obj.c: bpf-kernel.o
	xxd -i $< > $@
