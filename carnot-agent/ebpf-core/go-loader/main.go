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
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"
    "runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	TsNs       uint64
	Pid        uint32
	Comm       [16]byte
	Kind       uint8
	Success    bool
	_          [3]byte
	SslPtr     uint64
	Sni        [256]byte
	Groups     [128]byte
	Tid        uint32
	DurationNs uint64
	GroupID    int32
}

type handshake struct {
	Pid           uint32   `json:"pid"`
	Tid           uint32   `json:"tid"`
	Proc          string   `json:"proc"`
	Time          string   `json:"time"`
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
	groups        []string
	groupSelected string
	sslptr        string
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

func main() {
	var objPath, libssl, outPath, metricsPath string
	var evictTTL time.Duration
	var hashSNIMode, hashIPMode, hashKeyStr string
	flag.StringVar(&objPath, "obj", "openssl_handshake.bpf.o", "BPF object path")
	flag.StringVar(&libssl, "libssl", "/lib/x86_64-linux-gnu/libssl.so.3", "libssl.so.3 path")
	flag.StringVar(&outPath, "out", "runtime.jsonl", "Aggregated output JSONL (one per handshake)")
	flag.StringVar(&metricsPath, "metrics", "metrics.json", "Metrics JSON path (periodically written)")
	flag.DurationVar(&evictTTL, "evict-ttl", 2*time.Second, "Correlation TTL for partial handshakes")
	flag.StringVar(&hashSNIMode, "hash-sni", "none", "Hash mode for SNI: none|sha256|hmac")
	flag.StringVar(&hashIPMode, "hash-ip", "none", "Hash mode for client/server IPs (future): none|sha256|hmac")
	flag.StringVar(&hashKeyStr, "hash-key", "", "Key (hex or base64) for HMAC when hash-* mode is hmac")
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

	exe, err := link.OpenExecutable(libssl)
	if err != nil { log.Fatalf("open executable: %v", err) }
	type probe struct{ sym string; ret bool; prog string }
	probes := []probe{
		{"SSL_do_handshake", false, "SSL_do_handshake_enter"},
		{"SSL_do_handshake", true,  "SSL_do_handshake_exit"},
		{"SSL_connect", false, "SSL_connect_enter"},
		{"SSL_connect", true,  "SSL_connect_exit"},
		{"SSL_accept", false, "SSL_accept_enter"},
		{"SSL_accept", true,  "SSL_accept_exit"},
		{"SSL_set_tlsext_host_name", false, "SSL_set_tlsext_host_name_enter"},
		{"SSL_CTX_set1_groups_list", false, "SSL_CTX_set1_groups_list_enter"},
		// optional negotiated-group probes
		{"SSL_get_negotiated_group", true, "SSL_get_negotiated_group_exit"},
		{"SSL_get_shared_group", true, "SSL_get_shared_group_exit"},
		{"tls1_shared_group", true, "tls1_shared_group_exit"},
		{"tls1_get_shared_group", true, "tls1_get_shared_group_exit"},
	}
	probeStatus := make(map[string]string)
	probeErrors := make(map[string]string)
	for _, p := range probes {
		prog := coll.Programs[p.prog]
		if prog == nil { probeStatus[p.sym] = "missing"; continue }
		if p.ret {
			if _, err := exe.Uretprobe(p.sym, prog, nil); err != nil {
				probeStatus[p.sym] = "error"
				probeErrors[p.sym] = err.Error()
				log.Printf("attach uretprobe %s -> %s FAILED: %v", p.sym, p.prog, err)
			} else { probeStatus[p.sym] = "ok"; log.Printf("attach uretprobe %s -> %s OK", p.sym, p.prog) }
		} else {
			if _, err := exe.Uprobe(p.sym, prog, nil); err != nil {
				probeStatus[p.sym] = "error"
				probeErrors[p.sym] = err.Error()
				log.Printf("attach uprobe %s -> %s FAILED: %v", p.sym, p.prog, err)
			} else { probeStatus[p.sym] = "ok"; log.Printf("attach uprobe %s -> %s OK", p.sym, p.prog) }
		}
	}
	// Record unused negotiated-group probes explicitly if not already in map
	for _, sym := range []string{"SSL_get_negotiated_group","SSL_get_shared_group","tls1_shared_group","tls1_get_shared_group"} {
		if _, ok := probeStatus[sym]; !ok { probeStatus[sym] = "missing" }
	}
	// Build and log probe matrix line
	var keys []string; for k := range probeStatus { keys = append(keys, k) }
	sort.Strings(keys)
	var bldr []string
	for _, k := range keys { bldr = append(bldr, fmt.Sprintf("%s=%s", k, probeStatus[k])) }
	log.Printf("probe matrix: %s", strings.Join(bldr, ","))

	rd, err := ringbuf.NewReader(events); if err != nil { log.Fatalf("ringbuf: %v", err) }
	defer rd.Close()

	outf, err := os.Create(outPath); if err != nil { log.Fatalf("open out: %v", err) }
	defer outf.Close()

	// Key strictly by TID per requirements (thread reuse risk accepted with short TTL)
	key := func(tid uint32) uint64 { return uint64(tid) }
	cache := map[uint64]*partial{}
	var mu sync.Mutex
	metricsData := &metrics{ProbeStatus: probeStatus, ProbeErrors: probeErrors}
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
	for {
		rec, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed { break }
			metricsData.ReaderErrors++
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &evt); err == nil {
			metricsData.EventsReceived++
			kind := evt.Kind
			pid, tid := evt.Pid, evt.Tid
			proc := string(bytes.Trim(evt.Comm[:], "\x00"))
			sni := string(bytes.Trim(evt.Sni[:], "\x00"))
			gr := string(bytes.Trim(evt.Groups[:], "\x00"))
			k := key(tid)

			mu.Lock()
			p := cache[k]
			if p == nil { p = &partial{firstSeen: time.Now(), proc: proc}; cache[k] = p }
			switch kind {
			case 2: // SNI_SET
				p.sni = sni; p.sslptr = fmt.Sprintf("0x%x", evt.SslPtr)
			case 3: // GROUPS_SET
				if gr != "" { p.groups = append(p.groups, gr) }
			case 4: // GROUP_SELECTED
				if evt.GroupID != 0 { p.groupSelected = groupName(evt.GroupID) }
			case 1: // HANDSHAKE_RET
				hs := handshake{
					Pid: pid, Tid: tid, Proc: proc,
					Time: time.Unix(0, int64(evt.TsNs)).UTC().Format(time.RFC3339Nano),
					SNI: p.sni, Groups: p.groups, GroupSelected: p.groupSelected, Success: evt.Success, SSLPtr: p.sslptr,
				}
				// Apply hashing for SNI if enabled
				if hashSNIMode != "none" && hs.SNI != "" {
					hs.SNIHash = hashBytes([]byte(hs.SNI), hashSNIMode)
					hs.SNI = "" // remove plaintext
				}
				if evt.DurationNs > 0 {
					hs.DurationMs = float64(evt.DurationNs)/1e6
					durations = append(durations, hs.DurationMs)
				}
				enc, _ := json.Marshal(hs)
				outf.Write(enc); outf.Write([]byte("\n"))
				metricsData.HandshakesEmitted++
				if p.sni == "" { metricsData.HandshakesNoSNI++ }
				delete(cache, k)
			}
			mu.Unlock()
		}
	}
	// final summary
	if metricsData.EventsReceived > 0 {
		metricsData.KernelDropRate = float64(metricsData.KernelDrops) / float64(metricsData.EventsReceived)
	}
	log.Printf("FINAL metrics eventsReceived=%d handshakesEmitted=%d correlationTimeouts=%d cacheEvictions=%d kernel_drops=%d kernel_drop_rate=%.6f", 
		metricsData.EventsReceived, metricsData.HandshakesEmitted, metricsData.CorrelationTimeouts, metricsData.CacheEvictions, metricsData.KernelDrops, metricsData.KernelDropRate)
}
