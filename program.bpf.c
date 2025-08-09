// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    char comm[16];
    s64 size;
    u8 kind;
    void *dst;
    void *src;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

// Hook into the target CUDA API function
SEC("uprobe/cudaLaunchKernel")
int handle_cuda_launch(struct pt_regs *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // PID and process name
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Example: pull extra args (adjust indexes to match real function)
    e->size = PT_REGS_PARM1(ctx);   // s64 size
    e->kind = PT_REGS_PARM2(ctx);   // u8 kind
    e->dst  = (void *)PT_REGS_PARM3(ctx); // void* dst
    e->src  = (void *)PT_REGS_PARM4(ctx); // void* src

    bpf_ringbuf_submit(e, 0);
    return 0;
}
