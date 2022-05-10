# Useful commands:
#   make filter
#   ip link show $eth
#   sudo ip link set dev $eth xdp off
#   sudo ip link set dev $eth xdp obj ./bpf-kernel.o
#
# Built using LLVM/CLANG 10. Newer versions produce bigger filter.
# Since version 13 the resulting filter cannot be loaded due to "invalid access to packet"
# when "*ipv6_src  = ip6->daddr". But IPv6 header check is in xdp_redirect_dns_func()!

EXTRA_DIST = bpf-kernel-obj.c bpf-kernel.c

.PHONY: filter

filter:
	rm -f bpf-kernel.ll bpf-kernel.o bpf-kernel-obj.c
	clang -S -target bpf -Wall -O2 -emit-llvm -c -DNDEBUG -o bpf-kernel.ll -I/usr/include/x86_64-linux-gnu -include ../../config.h bpf-kernel.c
	llc -march=bpf -filetype=obj -o bpf-kernel.o bpf-kernel.ll
	xxd -i bpf-kernel.o > bpf-kernel-obj.c
