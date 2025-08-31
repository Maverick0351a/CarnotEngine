//go:build !cgo

package negotiated

// Lookup returns (groupName, true) if a negotiated group could be resolved for this SSL pointer.
// Stub (no-cgo) implementation returns no data.
func Lookup(libssl, sslptr string) (string, bool) {
	return "", false
}
