package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

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
	// Additional internal diagnostics (not required but useful)
	ReaderErrors        uint64  `json:"readerErrors"`
	HandshakesNoSNI     uint64  `json:"handshakesNoSNI"`
	P95DurationMs       float64 `json:"p95DurationMs"`
	P99DurationMs       float64 `json:"p99DurationMs"`
	ProbeStatus         map[string]string `json:"probe_status"`
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
	flag.StringVar(&objPath, "obj", "openssl_handshake.bpf.o", "BPF object path")
	flag.StringVar(&libssl, "libssl", "/lib/x86_64-linux-gnu/libssl.so.3", "libssl.so.3 path")
	flag.StringVar(&outPath, "out", "runtime.jsonl", "Aggregated output JSONL (one per handshake)")
	flag.StringVar(&metricsPath, "metrics", "metrics.json", "Metrics JSON path (periodically written)")
	flag.DurationVar(&evictTTL, "evict-ttl", 2*time.Second, "Correlation TTL for partial handshakes")
	// metrics log interval is fixed at 5s per requirements, but allow override via env in future if needed.
	flushInterval := 5 * time.Second
	flag.Parse()

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil { log.Fatalf("load spec: %v", err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { log.Fatalf("new collection: %v", err) }
	defer coll.Close()

	events := coll.Maps["events"]
	if events == nil { log.Fatalf("events ringbuf not found") }
	counters := coll.Maps["counters"] // may be nil if older BPF object; tolerate

	exe, err := link.OpenExecutable(libssl)
	if err != nil { log.Fatalf("open executable: %v", err) }
	type probe struct{ sym string; ret bool; prog string }
	probes := []probe{
		{"SSL_do_handshake", false, "SSL_do_handshake_enter"},
		{"SSL_do_handshake", true,  "SSL_do_handshake_exit"},
		{"SSL_set_tlsext_host_name", false, "SSL_set_tlsext_host_name_enter"},
		{"SSL_CTX_set1_groups_list", false, "SSL_CTX_set1_groups_list_enter"},
		// optional negotiated-group probes
		{"SSL_get_negotiated_group", true, "SSL_get_negotiated_group_exit"},
		{"SSL_get_shared_group", true, "SSL_get_shared_group_exit"},
		{"tls1_shared_group", true, "tls1_shared_group_exit"},
		{"tls1_get_shared_group", true, "tls1_get_shared_group_exit"},
	}
	probeStatus := make(map[string]string)
	for _, p := range probes {
		prog := coll.Programs[p.prog]
		if prog == nil { probeStatus[p.sym] = "missing"; continue }
		if p.ret {
			if _, err := exe.Uretprobe(p.sym, prog, nil); err != nil {
				probeStatus[p.sym] = "error"
			} else { probeStatus[p.sym] = "ok" }
		} else {
			if _, err := exe.Uprobe(p.sym, prog, nil); err != nil {
				probeStatus[p.sym] = "error"
			} else { probeStatus[p.sym] = "ok" }
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
	metricsData := &metrics{ProbeStatus: probeStatus}
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
				if counters != nil {
					var kd uint64
					if err := counters.Lookup(uint32(1), &kd); err == nil {
						metricsData.KernelDrops = kd
					}
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
				log.Printf("metrics eventsReceived=%d handshakesEmitted=%d correlationTimeouts=%d cacheEvictions=%d kernel_drops=%d", 
					metricsData.EventsReceived, metricsData.HandshakesEmitted, metricsData.CorrelationTimeouts, metricsData.CacheEvictions, metricsData.KernelDrops)
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
	log.Printf("FINAL metrics eventsReceived=%d handshakesEmitted=%d correlationTimeouts=%d cacheEvictions=%d kernel_drops=%d", 
		metricsData.EventsReceived, metricsData.HandshakesEmitted, metricsData.CorrelationTimeouts, metricsData.CacheEvictions, metricsData.KernelDrops)
}
