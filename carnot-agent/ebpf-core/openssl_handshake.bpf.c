// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
enum evt_kind { EVT_HANDSHAKE_RET=1, EVT_SNI_SET=2, EVT_GROUPS_SET=3, EVT_GROUP_SELECTED=4 };
struct event_t {
  __u64 ts_ns; __u32 pid; __u32 tid; char comm[TASK_COMM_LEN];
  __u8 kind; bool success; __u16 _pad; __u64 ssl_ptr;
  char sni[256]; char groups[128]; int group_id;
};
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 512*1024);} events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key,__u32); __type(value,__u64); __uint(max_entries,16384);} active_ssl SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries,2); __type(key,__u32); __type(value,__u64);} counters SEC(".maps");
static __always_inline void count_inc(__u32 idx){ __u64 init=0; bpf_map_update_elem(&counters,&idx,&init,BPF_NOEXIST); __u64* v=bpf_map_lookup_elem(&counters,&idx); if(v) __sync_fetch_and_add(v,1); }
static __inline __u32 get_tid(){ return (__u32)bpf_get_current_pid_tgid(); }
SEC("uprobe//libssl.so.3:SSL_do_handshake") int BPF_KPROBE(SSL_do_handshake_enter){ __u64 p=(__u64)PT_REGS_PARM1(ctx); __u32 tid=get_tid(); bpf_map_update_elem(&active_ssl,&tid,&p,BPF_ANY); return 0; }
SEC("uretprobe//libssl.so.3:SSL_do_handshake") int BPF_KRETPROBE(SSL_do_handshake_exit, int ret){
  __u32 tid=get_tid(); __u64 *pssl=bpf_map_lookup_elem(&active_ssl,&tid);
  struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e){count_inc(1); return 0;}
  e->ts_ns=bpf_ktime_get_ns(); __u64 pt=bpf_get_current_pid_tgid(); e->pid=pt>>32; e->tid=(__u32)pt; bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_HANDSHAKE_RET; e->success=(ret==1); e->ssl_ptr=pssl?*pssl:0; e->sni[0]='\0'; e->groups[0]='\0'; e->group_id=-1;
  bpf_ringbuf_submit(e,0); count_inc(0); if(pssl) bpf_map_delete_elem(&active_ssl,&tid); return 0; }
SEC("uprobe//libssl.so.3:SSL_set_tlsext_host_name") int BPF_KPROBE(SSL_set_tlsext_host_name_enter){
  const char* name=(const char*)PT_REGS_PARM2(ctx); struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e){count_inc(1); return 0;}
  e->ts_ns=bpf_ktime_get_ns(); __u64 pt=bpf_get_current_pid_tgid(); e->pid=pt>>32; e->tid=(__u32)pt; bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_SNI_SET; e->success=false; e->ssl_ptr=(__u64)PT_REGS_PARM1(ctx); bpf_probe_read_user_str(e->sni,sizeof(e->sni),name); e->groups[0]='\0'; e->group_id=-1;
  bpf_ringbuf_submit(e,0); count_inc(0); return 0; }
SEC("uprobe//libssl.so.3:SSL_CTX_set1_groups_list") int BPF_KPROBE(SSL_CTX_set1_groups_list_enter){
  const char* str=(const char*)PT_REGS_PARM2(ctx); struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e){count_inc(1); return 0;}
  e->ts_ns=bpf_ktime_get_ns(); __u64 pt=bpf_get_current_pid_tgid(); e->pid=pt>>32; e->tid=(__u32)pt; bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_GROUPS_SET; e->success=false; e->ssl_ptr=0; e->sni[0]='\0'; bpf_probe_read_user_str(e->groups,sizeof(e->groups),str); e->group_id=-1;
  bpf_ringbuf_submit(e,0); count_inc(0); return 0; }

// Negotiated group (best-effort). We try several potential symbols; not all may exist.
SEC("uretprobe//libssl.so.3:SSL_get_negotiated_group")
int BPF_KRETPROBE(SSL_get_negotiated_group_exit, int ret){
  struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e) return 0;
  e->ts_ns=bpf_ktime_get_ns(); e->pid=bpf_get_current_pid_tgid()>>32; e->tid=get_tid(); bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_GROUP_SELECTED; e->success=false; e->ssl_ptr=0; e->sni[0]='\0'; e->groups[0]='\0'; e->group_id=ret;
  bpf_ringbuf_submit(e,0); return 0;
}

SEC("uretprobe//libssl.so.3:SSL_get_shared_group")
int BPF_KRETPROBE(SSL_get_shared_group_exit, int ret){
  struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e) return 0;
  e->ts_ns=bpf_ktime_get_ns(); e->pid=bpf_get_current_pid_tgid()>>32; e->tid=get_tid(); bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_GROUP_SELECTED; e->success=false; e->ssl_ptr=0; e->sni[0]='\0'; e->groups[0]='\0'; e->group_id=ret;
  bpf_ringbuf_submit(e,0); return 0;
}

SEC("uretprobe//libssl.so.3:tls1_shared_group")
int BPF_KRETPROBE(tls1_shared_group_exit, int ret){
  struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e) return 0;
  e->ts_ns=bpf_ktime_get_ns(); e->pid=bpf_get_current_pid_tgid()>>32; e->tid=get_tid(); bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_GROUP_SELECTED; e->success=false; e->ssl_ptr=0; e->sni[0]='\0'; e->groups[0]='\0'; e->group_id=ret;
  bpf_ringbuf_submit(e,0); return 0;
}

SEC("uretprobe//libssl.so.3:tls1_get_shared_group")
int BPF_KRETPROBE(tls1_get_shared_group_exit, int ret){
  struct event_t *e=bpf_ringbuf_reserve(&events,sizeof(*e),0); if(!e) return 0;
  e->ts_ns=bpf_ktime_get_ns(); e->pid=bpf_get_current_pid_tgid()>>32; e->tid=get_tid(); bpf_get_current_comm(&e->comm,sizeof(e->comm));
  e->kind=EVT_GROUP_SELECTED; e->success=false; e->ssl_ptr=0; e->sni[0]='\0'; e->groups[0]='\0'; e->group_id=ret;
  bpf_ringbuf_submit(e,0); return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
