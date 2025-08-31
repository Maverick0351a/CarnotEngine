BPF_CLANG ?= clang
BPFTOOL ?= bpftool

all: vmlinux.h openssl_handshake.bpf.o

vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		which $(BPFTOOL) >/dev/null 2>&1 || { echo "bpftool not found (sudo apt-get install -y bpftool)"; exit 1; }; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		echo "Generated vmlinux.h"; \
	fi

openssl_handshake.bpf.o: openssl_handshake.bpf.c vmlinux.h
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c openssl_handshake.bpf.c -o openssl_handshake.bpf.o

.PHONY: clean
clean:
	rm -f openssl_handshake.bpf.o vmlinux.h
