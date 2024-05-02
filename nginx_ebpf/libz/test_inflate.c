#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

BPF_HASH(inflate_stats, u32, u64);

int inflate_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = inflate_stats.lookup(&pid);

    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        inflate_stats.update(&pid, &init_val);
    }
    return 0;
}
