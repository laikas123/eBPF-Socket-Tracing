#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "socket_mon.h"

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "do_execve";
const char fentry_msg[16] = "fentry_execve";
const char tp_msg[16] = "tp_execve";
const char tp_msg2[16] = "tp_openat";
const char tp_msg3[16] = "pseudocat";
const char tp_msg4[16] = "read";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_socket SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 256 KB */);
} output_read SEC(".maps");









SEC("tp/syscalls/sys_enter_socket")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    
    struct socket_data_t data = {}; 


    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.domain = (int) BPF_CORE_READ(ctx, args[0]);
    data.type = (int) BPF_CORE_READ(ctx, args[1]);
    data.protocol = (int) BPF_CORE_READ(ctx, args[2]);


    //send data to buffer to be polled by userspace
    bpf_ringbuf_output(&output_socket, &data, sizeof(data), 0);   

    return 0;
}


SEC("tp/syscalls/sys_enter_socket")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    
    struct socket_data_t data = {}; 


    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.domain = (int) BPF_CORE_READ(ctx, args[0]);
    data.type = (int) BPF_CORE_READ(ctx, args[1]);
    data.protocol = (int) BPF_CORE_READ(ctx, args[2]);


    //send data to buffer to be polled by userspace
    bpf_ringbuf_output(&output_socket, &data, sizeof(data), 0);   

    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
