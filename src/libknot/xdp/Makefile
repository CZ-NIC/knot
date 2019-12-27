

all: bpf-kernel.o

bpf-kernel.ll: bpf-kernel.c
	clang -S -target bpf -Wall -O2 -emit-llvm -c -g -DNDEBUG -o bpf-kernel.ll bpf-kernel.c

bpf-kernel.o: bpf-kernel.ll
	llc -march=bpf -filetype=obj -o bpf-kernel.o bpf-kernel.ll

clean:
	rm -f bpf-kernel.ll bpf-kernel.o

