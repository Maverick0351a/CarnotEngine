BPF_CLANG ?= clang
BPFTOOL ?= bpftool
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include -I/usr/include/bpf

all: headers_check vmlinux.h openssl_handshake.bpf.o

headers_check:
	@if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then \
		echo "ERROR: Missing /usr/include/bpf/bpf_helpers.h (install libbpf-dev)"; exit 1; \
	fi

vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		which $(BPFTOOL) >/dev/null 2>&1 || { echo "bpftool not found (sudo apt-get install -y bpftool)"; exit 1; }; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		echo "Generated vmlinux.h"; \
	fi

openssl_handshake.bpf.o: openssl_handshake.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c openssl_handshake.bpf.c -o openssl_handshake.bpf.o

.PHONY: clean
clean:
	rm -f openssl_handshake.bpf.o vmlinux.h
