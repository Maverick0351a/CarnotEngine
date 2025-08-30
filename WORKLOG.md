# WORKLOG

- Init consolidated repo.
- Implemented eBPF handshake correlation (Task 01):
	- Added TID-keyed cache with 2s TTL, metrics logging every 5s.
	- Metrics: eventsReceived, handshakesEmitted, correlationTimeouts, cacheEvictions, kernel_drops.
	- Output aggregated handshake JSONL to runtime.jsonl.
	- Commands:
		- cd carnot-agent/ebpf-core; make
		- cd go-loader && go build -o bin/carnot-ebpf-loader ./...
		- sudo ./bin/carnot-ebpf-loader -obj ../openssl_handshake.bpf.o -out runtime.jsonl -libssl /lib/x86_64-linux-gnu/libssl.so.3
		- curl -sS https://example.org >$null
	- Expected: runtime.jsonl lines containing pid, tid, sni, groups_offered, success; low kernel_drops & correlationTimeouts.
- Task 01b (Negotiated Group Extraction):
	- Added optional cgo shim (dlopen/dlsym) to call SSL_get_shared_group if exported.
	- Emits negotiated_group in handshake JSON when available.
	- Limitations: only dynamic libssl.so.3, skips statically linked or stripped symbols, pointer validity best-effort, hybrid group IDs placeholder mapping.
