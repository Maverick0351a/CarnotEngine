BPF_CLANG ?= clang
all:
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c openssl_handshake.bpf.c -o openssl_handshake.bpf.o
