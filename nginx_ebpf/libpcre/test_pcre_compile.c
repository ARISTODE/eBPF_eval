#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

BPF_HASH(compile_stats, u32, u64);

int pcre2_compile_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = compile_stats.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        compile_stats.update(&pid, &init_val);
    }
    return 0;
}
