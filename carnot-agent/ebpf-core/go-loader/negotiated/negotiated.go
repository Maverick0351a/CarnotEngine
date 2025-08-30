//go:build linux && cgo

package negotiated

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static void* lib_handle = NULL;
static int (*p_SSL_get_shared_group)(void*, int) = NULL;
static int resolved = 0; // 0=unknown, 1=ok, -1=unavailable

static int ensure_loaded(const char* path){
  if(resolved!=0) return resolved==1;
  lib_handle = dlopen(path, RTLD_LAZY|RTLD_LOCAL);
  if(!lib_handle){ resolved=-1; return 0; }
  p_SSL_get_shared_group = (int(*)(void*,int))dlsym(lib_handle, "SSL_get_shared_group");
  if(!p_SSL_get_shared_group){ resolved=-1; return 0; }
  resolved=1; return 1;
}

static int get_shared_group(const char* path, void* ssl){
  if(!ensure_loaded(path)) return -1;
  return p_SSL_get_shared_group(ssl,0);
}
*/
import "C"
import (
	"fmt"
	"log"
	"sync"
	"unsafe"
)

var once sync.Once
var available bool

// Lookup tries to resolve negotiated shared group via SSL_get_shared_group if exported.
// libPath: path to libssl.so.3 provided by user.
// sslPtr: textual hex pointer (e.g., "0x7f..."), we parse to uintptr.
func Lookup(libPath string, sslPtr string) (string, bool) {
	if sslPtr == "" || sslPtr == "0x0" {
		return "", false
	}
	once.Do(func(){
		cpath := C.CString(libPath)
		defer C.free(unsafe.Pointer(cpath))
		if C.ensure_loaded(cpath) == 1 { available = true } else { log.Printf("negotiated: SSL_get_shared_group unavailable for %s", libPath) }
	})
	if !available { return "", false }
	// parse pointer
	var p uintptr
	_, err := fmt.Sscanf(sslPtr, "0x%X", &p)
	if err != nil { return "", false }
	gid := int(C.get_shared_group(C.CString(libPath), unsafe.Pointer(p)))
	if gid <= 0 { return "", false }
	return mapGroup(gid), true
}

// mapGroup converts OpenSSL group id to textual hybrid/PQC label if known.
func mapGroup(id int) string {
	switch id {
	case 29: return "X25519" // baseline
	// Placeholder mapping examples for hybrid groups; adjust when interop lab defines real codes.
	case 5001: return "X25519MLKEM768"
	case 5002: return "X25519MLKEM1024"
	case 5003: return "secp256r1MLKEM768"
	default:
		return fmt.Sprintf("grp_%d", id)
	}
}
