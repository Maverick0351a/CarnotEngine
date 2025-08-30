# Task 01b — Negotiated Group Extraction (Optional, Safe)
**Prompt:**
Implement an optional cgo shim in `carnot-agent/ebpf-core/go-loader/negotiated/` that uses `dlopen`/`dlsym` on `libssl.so.3` to call a stable accessor (e.g., `SSL_get_shared_group(ssl, 0)` if exported) and return a textual group name (e.g., `X25519MLKEM768`). Wire it in on handshake.ret to fill `negotiated_group`. If unavailable, leave empty and log once per process.

**Commands:**
```bash
cd carnot-agent/ebpf-core/go-loader
go build -o bin/carnot-ebpf-loader ./...
```

**Acceptance:**
- With the interop lab offering hybrid groups, at least one handshake shows a non-empty `negotiated_group`.
- WORKLOG documents limitations (no support for statically linked TLS, etc.).
