// program.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/filter.h>
#include <gadget/types.h>
#include <gadget/mntns.h>

char LICENSE[] SEC("license") = "GPL";

// Declare the tracer buffer named "events" with a 256KiB size
GADGET_TRACER_MAP(events, 1024 * 256);

struct event {
    gadget_mntns_id mntns_id;  // container context for enrichment
    u32 pid;
    char comm[TASK_COMM_LEN];
    s64 size;
    u8 kind;
    void *dst;
    void *src;
};

SEC("uprobe/cudaMemcpyAsync")
int trace_cuda_memcpy(struct pt_regs *ctx) {
    if (gadget_should_discard_data_current())
        return 0;

    struct event *evt = gadget_reserve_buf(&events, sizeof(*evt));
    if (!evt)
        return 0;

    // Populate basic process & container info
    evt->mntns_id = gadget_get_current_mntns_id();
    evt->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Capture CUDA parameters; adjust if signature differs
    evt->dst  = (void *)PT_REGS_PARM1(ctx);
    evt->src  = (void *)PT_REGS_PARM2(ctx);
    evt->size = (s64)PT_REGS_PARM3(ctx);
    evt->kind = (u8)PT_REGS_PARM4(ctx);

    gadget_submit_buf(ctx, &events, evt, sizeof(*evt));
    return 0;
}
