//go:build cgo && !linux

package negotiated

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>

typedef int (*shared_group_fn)(void* ssl, int idx);

static int call_shared_group(void* fn, void* ssl, int idx) {
	if (!fn) return -1;
	return ((shared_group_fn)fn)(ssl, idx);
}
*/
import "C"
import ()

// (Simplified) attempt to resolve negotiated group via libssl exported symbol.
// This is illustrative; real implementation would search multiple symbols.
func Lookup(libssl, sslptr string) (string, bool) { return "", false }
