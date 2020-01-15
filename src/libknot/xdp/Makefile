
all: bpf-kernel.o

# Missing /usr/include/asm/types.h, so /usr/include/x86_64-linux-gnu
bpf-kernel.ll: bpf-kernel.c
	clang -S -target bpf -Wall -O2 -emit-llvm -c -DNDEBUG -o bpf-kernel.ll -I/usr/include/x86_64-linux-gnu bpf-kernel.c

bpf-kernel.o: bpf-kernel.ll
	llc -march=bpf -filetype=obj -o bpf-kernel.o bpf-kernel.ll
	xxd -i bpf-kernel.o > bpf-kernel-obj.c

clean:
	rm -f bpf-kernel.ll bpf-kernel.o bpf-kernel-obj.c

