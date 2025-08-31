package main
import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"crypto/sha256"
	"crypto/hmac"
	"encoding/hex"
	"encoding/base64"
	"unicode/utf8"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"
	"runtime"
    "unsafe"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// event mirrors struct event_t (keep sizes in sync if modified)
// C struct event_t {
//  u64 ts_ns; u32 pid; u32 tid; char comm[16];
//  u8 kind; bool success; u16 _pad; u64 ssl_ptr;
//  char sni[256]; char groups[128]; int group_id; long ret; u8 func_id;
// };
type event struct {
	TsNs    uint64
	Pid     uint32
	Tid     uint32
	Comm    [16]byte
	Kind    uint8
	Success bool
	Pad     uint16
	SslPtr  uint64
	Sni     [256]byte
	Groups  [128]byte
	GroupID int32
	Ret     int64
	FuncID  uint8
}

type handshake struct {
	Pid           uint32   `json:"pid"`
	Tid           uint32   `json:"tid"`
	Proc          string   `json:"proc"`
	TimeWall      string   `json:"time_wall"`
	TimeMonoNs    int64    `json:"time_mono_ns"`
	SNI           string   `json:"sni,omitempty"`
	SNIHash       string   `json:"sni_hash,omitempty"`
	Groups        []string `json:"groups_offered,omitempty"`
	GroupSelected string   `json:"group_selected,omitempty"`
	Success       bool     `json:"success"`
	SSLPtr        string   `json:"ssl_ptr,omitempty"`
	DurationMs    float64  `json:"duration_ms,omitempty"`
}

type partial struct {
	firstSeen     time.Time
	proc          string
	sni           string
	sniHash       string // may be computed if original invalid or privacy mode
	groups        []string
	groupSelected string
	sslptr        string
	retConnect    int64
	retDoHS       int64
	retConnectEx  int64
	retAccept     int64
}

// metrics matches acceptance criteria naming.
type metrics struct {
	EventsReceived      uint64  `json:"eventsReceived"`
	HandshakesEmitted   uint64  `json:"handshakesEmitted"`
	CorrelationTimeouts uint64  `json:"correlationTimeouts"`
	CacheEvictions      uint64  `json:"cacheEvictions"`
	KernelDrops         uint64  `json:"kernel_drops"`
	KernelDropRate      float64 `json:"kernel_drop_rate"`
	// Additional internal diagnostics (not required but useful)
	ReaderErrors        uint64  `json:"readerErrors"`
	HandshakesNoSNI     uint64  `json:"handshakesNoSNI"`
	P95DurationMs       float64 `json:"p95DurationMs"`
	P99DurationMs       float64 `json:"p99DurationMs"`
	ProbeStatus         map[string]string `json:"probe_status"`
	ProbeErrors         map[string]string `json:"probe_errors,omitempty"`
	ProbeStatusPaths    map[string]map[string]string `json:"probe_status_paths,omitempty"`
	BuildGitSHA         string  `json:"build_git_sha,omitempty"`
	BpfToolVersion      string  `json:"bpftool_version,omitempty"`
	GoVersion           string  `json:"go_version,omitempty"`
	BuildHost           string  `json:"build_host,omitempty"`
}

func groupName(id int32) string {
	switch id {
	case 23: return "secp256r1"
	case 24: return "secp384r1"
	case 29: return "x25519"
	case 30: return "x448"
	default:
		if id > 0 {
			return fmt.Sprintf("iana_grp_%d", id)
		}
		return ""
	}
}

func sanitizeSNI(raw string) (string, string) {
	raw = strings.TrimSpace(strings.Trim(raw, "\x00"))
	if raw == "" || !utf8.ValidString(raw) || strings.IndexFunc(raw, func(r rune) bool { return r < 32 }) >= 0 || len(raw) > 253 {
		sum := sha256.Sum256([]byte(raw))
		return "", hex.EncodeToString(sum[:])
	}
	return raw, ""
}

func main() {
	var objPath, libssl, outPath, metricsPath string
	var evictTTL time.Duration
	var hashSNIMode, hashIPMode, hashKeyStr string
	var ringSize int
	flag.StringVar(&objPath, "obj", "openssl_handshake.bpf.o", "BPF object path")
	flag.StringVar(&libssl, "libssl", "/lib/x86_64-linux-gnu/libssl.so.3", "libssl.so.3 path")
	flag.StringVar(&outPath, "out", "runtime.jsonl", "Aggregated output JSONL (one per handshake)")
	flag.StringVar(&metricsPath, "metrics", "metrics.json", "Metrics JSON path (periodically written)")
	flag.DurationVar(&evictTTL, "evict-ttl", 2*time.Second, "Correlation TTL for partial handshakes")
	flag.StringVar(&hashSNIMode, "hash-sni", "none", "Hash mode for SNI: none|sha256|hmac")
	flag.StringVar(&hashIPMode, "hash-ip", "none", "Hash mode for client/server IPs (future): none|sha256|hmac")
	flag.StringVar(&hashKeyStr, "hash-key", "", "Key (hex or base64) for HMAC when hash-* mode is hmac")
	flag.IntVar(&ringSize, "rb", 1<<20, "Ring buffer size hint (must match BPF if larger)")
	// metrics log interval is fixed at 5s per requirements, but allow override via env in future if needed.
	flushInterval := 5 * time.Second
	flag.Parse()

	parseKey := func(k string) ([]byte, error) {
		if k == "" { return nil, fmt.Errorf("empty key") }
		// try hex
		if b, err := hex.DecodeString(k); err == nil { return b, nil }
		// try base64 std
		if b, err := base64.StdEncoding.DecodeString(k); err == nil { return b, nil }
		// try base64 URL
		if b, err := base64.URLEncoding.DecodeString(k); err == nil { return b, nil }
		return nil, fmt.Errorf("unable to decode key (expect hex or base64)")
	}

	if hashSNIMode != "none" && hashSNIMode != "sha256" && hashSNIMode != "hmac" { log.Fatalf("invalid --hash-sni mode: %s", hashSNIMode) }
	if hashIPMode != "none" && hashIPMode != "sha256" && hashIPMode != "hmac" { log.Fatalf("invalid --hash-ip mode: %s", hashIPMode) }
	var hmacKey []byte
	if (hashSNIMode == "hmac" || hashIPMode == "hmac") {
		if hashKeyStr == "" { log.Fatalf("--hash-key required for hmac mode") }
		var err error
		hmacKey, err = parseKey(hashKeyStr)
		if err != nil { log.Fatalf("parse hash key: %v", err) }
	}

	hashBytes := func(data []byte, mode string) string {
		if len(data) == 0 || mode == "none" { return "" }
		if mode == "sha256" {
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:])
		}
		if mode == "hmac" {
			h := hmac.New(sha256.New, hmacKey)
			h.Write(data)
			return hex.EncodeToString(h.Sum(nil))
		}
		return ""
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil { log.Fatalf("load spec: %v", err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { log.Fatalf("new collection: %v", err) }
	defer coll.Close()

	events := coll.Maps["events"]
	if events == nil { log.Fatalf("events ringbuf not found") }
	dropCounters := coll.Maps["drop_counters"] // new map for ringbuf reserve drops

	// Multi-attach: discover all libssl.so.3 paths plus the provided one.
	findLibs := func(primary string) []string {
		candidates := []string{}
		seen := map[string]struct{}{}
		add := func(p string){ if p=="" {return}; if _,ok:=seen[p]; !ok { candidates = append(candidates, p); seen[p]=struct{}{} } }
		add(primary)
		searchDirs := []string{"/usr/lib/x86_64-linux-gnu","/lib/x86_64-linux-gnu","/usr/local/lib","/lib64"}
		for _, d := range searchDirs {
			matches, _ := filepath.Glob(filepath.Join(d, "libssl.so.3"))
			for _, m := range matches { add(m) }
		}
		return candidates
	}
	libs := findLibs(libssl)
	// Deduplicate by inode (dev+ino)
	type di struct { dev uint64; ino uint64 }
	unique := []string{}
	seenInode := map[di]string{}
	for _, p := range libs {
		if st, err := os.Stat(p); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				key := di{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}
				if _, exists := seenInode[key]; !exists { seenInode[key]=p; unique = append(unique, p) }
			}
		}
	}
	log.Printf("discovered libssl candidates (unique by inode): %v", unique)
	type probe struct{ sym string; ret bool; prog string }
	probes := []probe{
		{"SSL_do_handshake", false, "SSL_do_handshake_enter"},
		{"SSL_do_handshake", true,  "SSL_do_handshake_exit"},
		{"SSL_connect", false, "SSL_connect_enter"},
		{"SSL_connect", true,  "SSL_connect_exit"},
		{"SSL_connect_ex", false, "SSL_connect_ex_enter"},
		{"SSL_connect_ex", true,  "SSL_connect_ex_exit"},
		{"SSL_accept", false, "SSL_accept_enter"},
		{"SSL_accept", true,  "SSL_accept_exit"},
		{"SSL_ctrl", false, "SSL_ctrl_enter"},
		{"SSL_set_tlsext_host_name", false, "SSL_set_tlsext_host_name_enter"},
		{"SSL_CTX_set1_groups_list", false, "SSL_CTX_set1_groups_list_enter"},
		{"SSL_get_negotiated_group", true, "SSL_get_negotiated_group_exit"},
		{"SSL_get_shared_group", true, "SSL_get_shared_group_exit"},
		{"tls1_shared_group", true, "tls1_shared_group_exit"},
		{"tls1_get_shared_group", true, "tls1_get_shared_group_exit"},
	}
	probeStatus := make(map[string]string) // overall (any success => ok)
	probeErrors := make(map[string]string) // first error encountered
	probeStatusPaths := make(map[string]map[string]string)
	var heldLinks []link.Link
	for _, path := range unique {
		perPath := make(map[string]string)
		exe, err := link.OpenExecutable(path)
		if err != nil {
			log.Printf("open executable %s failed: %v", path, err)
			for _, p := range probes { if _, ok := perPath[p.sym]; !ok { perPath[p.sym] = "open_error" } }
			probeStatusPaths[path] = perPath
			continue
		}
		for _, p := range probes {
			prog := coll.Programs[p.prog]
			if prog == nil { perPath[p.sym] = "missing_prog"; if _,ok:=probeStatus[p.sym]; !ok { probeStatus[p.sym]="missing" }; continue }
			var lnk link.Link; var aerr error
			if p.ret { lnk, aerr = exe.Uretprobe(p.sym, prog, nil) } else { lnk, aerr = exe.Uprobe(p.sym, prog, nil) }
			if aerr != nil {
				perPath[p.sym] = "error"
				if _, ok := probeErrors[p.sym]; !ok { probeErrors[p.sym] = aerr.Error() }
				if _, ok := probeStatus[p.sym]; !ok { probeStatus[p.sym] = "error" }
				log.Printf("attach %s %s (%s) FAILED on %s: %v", func(b bool) string { if b { return "uretprobe" }; return "uprobe" }(p.ret), p.sym, p.prog, path, aerr)
			} else {
				perPath[p.sym] = "ok"
				heldLinks = append(heldLinks, lnk)
				if probeStatus[p.sym] != "ok" { probeStatus[p.sym] = "ok" }
				log.Printf("attach %s %s (%s) OK on %s", func(b bool) string { if b { return "uretprobe" }; return "uprobe" }(p.ret), p.sym, p.prog, path)
			}
		}
		probeStatusPaths[path] = perPath
	}
	// ensure negotiated-group probes appear in overall map
	for _, sym := range []string{"SSL_get_negotiated_group","SSL_get_shared_group","tls1_shared_group","tls1_get_shared_group"} {
		if _, ok := probeStatus[sym]; !ok { probeStatus[sym] = "missing" }
	}
	// Log consolidated matrix
	var keys []string; for k := range probeStatus { keys = append(keys, k) }
	sort.Strings(keys)
	var bldr []string
	for _, k := range keys { bldr = append(bldr, fmt.Sprintf("%s=%s", k, probeStatus[k])) }
	log.Printf("probe matrix (overall): %s", strings.Join(bldr, ","))
	// Log per-path summary
	for path, m := range probeStatusPaths {
		var ks []string; for k := range m { ks = append(ks, k) }
		sort.Strings(ks)
		var line []string
		for _, k := range ks { line = append(line, fmt.Sprintf("%s=%s", k, m[k])) }
		log.Printf("probe matrix [%s]: %s", path, strings.Join(line, ","))
	}

	rd, err := ringbuf.NewReader(events); if err != nil { log.Fatalf("ringbuf: %v", err) }
	defer rd.Close()

	outf, err := os.Create(outPath); if err != nil { log.Fatalf("open out: %v", err) }
	defer outf.Close()

	// Key strictly by TID per requirements (thread reuse risk accepted with short TTL)
	key := func(tid uint32) uint64 { return uint64(tid) }
	cache := map[uint64]*partial{}
	var mu sync.Mutex
	metricsData := &metrics{ProbeStatus: probeStatus, ProbeErrors: probeErrors, ProbeStatusPaths: probeStatusPaths}
	// Populate build/environment metadata (non-fatal best-effort)
	metricsData.BuildGitSHA = os.Getenv("GITHUB_SHA")
	if metricsData.BuildGitSHA == "" { metricsData.BuildGitSHA = os.Getenv("COMMIT_SHA") }
	if metricsData.BuildGitSHA == "" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil { metricsData.BuildGitSHA = strings.TrimSpace(string(out)) }
	}
	if out, err := exec.Command("bpftool", "version").Output(); err == nil {
		metricsData.BpfToolVersion = strings.TrimSpace(string(out))
	}
	metricsData.GoVersion = runtime.Version()
	if h, err := os.Hostname(); err == nil { metricsData.BuildHost = h }
	durations := make([]float64, 0, 4096)

	evict := func(now time.Time){
		mu.Lock(); defer mu.Unlock()
		for k,v := range cache {
			if now.Sub(v.firstSeen) > evictTTL {
				metricsData.CorrelationTimeouts++
				metricsData.CacheEvictions++
				delete(cache, k)
			}
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt); defer cancel()
	tick := time.NewTicker(flushInterval); defer tick.Stop()

	go func(){
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				// compute durations percentiles (naive sort; low volume expected)
				if n := len(durations); n>0 {
					cp := append([]float64(nil), durations...)
					for i:=0;i<n-1;i++{ for j:=i+1;j<n;j++{ if cp[j]<cp[i]{ cp[i],cp[j]=cp[j],cp[i] } } }
					i95 := int(float64(n)*0.95)-1; if i95<0 { i95=0 }
					i99 := int(float64(n)*0.99)-1; if i99<0 { i99=0 }
					metricsData.P95DurationMs = cp[i95]
					metricsData.P99DurationMs = cp[i99]
					durations = durations[:0]
				}
				// refresh kernel drops if available
				if dropCounters != nil {
					var kd uint64
					if err := dropCounters.Lookup(uint32(0), &kd); err == nil {
						metricsData.KernelDrops = kd
					}
				}
				if metricsData.EventsReceived > 0 {
					metricsData.KernelDropRate = float64(metricsData.KernelDrops) / float64(metricsData.EventsReceived)
				} else {
					metricsData.KernelDropRate = 0
				}
				// include probe matrix each flush
				var keys []string; for k := range metricsData.ProbeStatus { keys = append(keys, k) }
				sort.Strings(keys)
				var bldr []string
				for _, k := range keys { bldr = append(bldr, fmt.Sprintf("%s=%s", k, metricsData.ProbeStatus[k])) }
				log.Printf("probe matrix: %s", strings.Join(bldr, ","))
				// write metrics JSON (best-effort)
				b, _ := json.MarshalIndent(metricsData, "", "  ")
				tmp := metricsPath + ".tmp"
				_ = os.WriteFile(tmp, b, 0644)
				_ = os.Rename(tmp, metricsPath)
				// TTL eviction
				evict(time.Now())
				// human log line
				log.Printf("metrics eventsReceived=%d handshakesEmitted=%d correlationTimeouts=%d cacheEvictions=%d kernel_drops=%d kernel_drop_rate=%.6f", 
					metricsData.EventsReceived, metricsData.HandshakesEmitted, metricsData.CorrelationTimeouts, metricsData.CacheEvictions, metricsData.KernelDrops, metricsData.KernelDropRate)
			}
		}
	}()

	var evt event
	expectedSize := int(unsafe.Sizeof(event{}))
	workers := 4
	jobs := make(chan []byte, 1024)
	var wg sync.WaitGroup
	process := func(raw []byte){
		if len(raw) != expectedSize { metricsData.ReaderErrors++; return }
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil { metricsData.ReaderErrors++; return }
		metricsData.EventsReceived++
		kind := evt.Kind
		pid, tid := evt.Pid, evt.Tid
		proc := string(bytes.Trim(evt.Comm[:], "\x00"))
		sniRaw := string(bytes.Trim(evt.Sni[:], "\x00"))
		gr := string(bytes.Trim(evt.Groups[:], "\x00"))
		k := key(tid)
		mono := int64(evt.TsNs)

		mu.Lock()
		p := cache[k]
		if p == nil { p = &partial{firstSeen: time.Now(), proc: proc}; cache[k] = p }
		switch kind {
		case 2,3: // SNI_SET
			if p.sni == "" && p.sniHash == "" { // first one wins
				clean, h := sanitizeSNI(sniRaw)
				p.sni = clean
				if clean == "" { p.sniHash = h } else if hashSNIMode != "none" { // privacy mode hashing
					p.sniHash = hashBytes([]byte(clean), hashSNIMode)
					p.sni = ""
				}
			}
			p.sslptr = fmt.Sprintf("0x%x", evt.SslPtr)
		case 3: // GROUPS_SET (note: value 3 reused earlier; groups event originally 3; if collision treat via kind value separation in C would be better)
			if gr != "" { p.groups = append(p.groups, gr) }
		case 4: // GROUP_SELECTED
			if evt.GroupID != 0 { p.groupSelected = groupName(evt.GroupID) }
		case 1: // HANDSHAKE_RET
			// Record return codes
			switch evt.FuncID { case 1: p.retDoHS = evt.Ret; case 2: p.retConnect = evt.Ret; case 3: p.retConnectEx = evt.Ret; case 4: p.retAccept = evt.Ret }
			// Compute success across any positive return
			success := p.retDoHS>0 || p.retConnect>0 || p.retConnectEx>0 || p.retAccept>0 || evt.Success
			hs := handshake{
				Pid: pid, Tid: tid, Proc: proc,
				TimeWall: time.Now().UTC().Format(time.RFC3339Nano),
				TimeMonoNs: mono,
				SNI: p.sni, Groups: p.groups, GroupSelected: p.groupSelected, Success: success, SSLPtr: p.sslptr,
			}
			if p.sniHash != "" { hs.SNIHash = p.sniHash }
			enc, _ := json.Marshal(hs)
			outf.Write(enc); outf.Write([]byte("\n"))
			metricsData.HandshakesEmitted++
			if p.sni == "" && p.sniHash == "" { metricsData.HandshakesNoSNI++ }
			delete(cache, k)
		}
		mu.Unlock()
	}
	for i:=0;i<workers;i++ { wg.Add(1); go func(){ defer wg.Done(); for raw := range jobs { process(raw) } }() }
	for {
		rec, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed { break }
			metricsData.ReaderErrors++
			continue
		}
		cp := make([]byte, len(rec.RawSample))
		copy(cp, rec.RawSample)
		jobs <- cp
	}
	close(jobs); wg.Wait()
	// final summary
	// final summary
	if metricsData.EventsReceived > 0 {
		metricsData.KernelDropRate = float64(metricsData.KernelDrops) / float64(metricsData.EventsReceived)
	}
	// Attempt to list first symbols for diagnostic (best-effort)
	if libssl != "" {
		cmd := exec.Command("bash","-c", fmt.Sprintf("(command -v nm >/dev/null 2>&1 && nm -D %s | head -n 50) || (command -v llvm-objdump >/dev/null 2>&1 && llvm-objdump -T %s | head -n 50) || true", libssl, libssl))
		if out, err := cmd.CombinedOutput(); err == nil {
			log.Printf("libssl symbols (truncated):\n%s", string(out))
		}
	}
	log.Printf("FINAL metrics eventsReceived=%d handshakesEmitted=%d correlationTimeouts=%d cacheEvictions=%d kernel_drops=%d kernel_drop_rate=%.6f", 
		metricsData.EventsReceived, metricsData.HandshakesEmitted, metricsData.CorrelationTimeouts, metricsData.CacheEvictions, metricsData.KernelDrops, metricsData.KernelDropRate)
}
