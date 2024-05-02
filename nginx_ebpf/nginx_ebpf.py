from bcc import BPF

# eBPF program
ebpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Define the structure for PCRE2 real code
struct pcre2_real_code {
    void *memctl;
    const uint8_t *tables;
    void *executable_jit;
    uint8_t start_bitmap[32];
    uint32_t blocksize;
    uint32_t magic_number;
    uint32_t compile_options;
    uint32_t overall_options;
    uint32_t extra_options;
    uint32_t flags;
    uint32_t limit_heap;
    uint32_t limit_match;
    uint32_t limit_depth; uint32_t first_codeunit;
    uint32_t last_codeunit;
    uint16_t bsr_convention;
    uint16_t newline_convention;
    uint16_t max_lookbehind;
    uint16_t minlength;
    uint16_t top_bracket;
    uint16_t top_backref;
    uint16_t name_entry_size;
    uint16_t name_count;
};

// BPF map to store the real code data
BPF_HASH(real_code_map, u64, struct pcre2_real_code);

// Instrumentation function for pcre2_compile
int pcre2_compile_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    // Get the pointer to the real code from the return value
    struct pcre2_real_code *real_code = (struct pcre2_real_code *)PT_REGS_RC(ctx);

    // Apply fine-grained data access policies

    // Example policy: Check if the magic number matches the expected value
    uint32_t magic_number;
    bpf_probe_read(&magic_number, sizeof(magic_number), &real_code->magic_number);
    if (magic_number != 0x50435245) {
        // Log an event or take appropriate action
        bpf_trace_printk("Invalid magic number\\n");
    }

    // Example policy: Check if the compile options contain unsupported flags
    uint32_t compile_options;
    bpf_probe_read(&compile_options, sizeof(compile_options), &real_code->compile_options);
    if (compile_options & 0x80000000) {
        // Log an event or take appropriate action
        bpf_trace_printk("Unsupported compile options\\n");
    }

    // Store the real code data in the BPF map
    real_code_map.update(&pid, real_code);

    return 0;
}

// Instrumentation function for pcre2_match
int pcre2_match_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    // Retrieve the real code data from the BPF map
    struct pcre2_real_code *real_code = real_code_map.lookup(&pid);
    if (real_code) {
        // Apply fine-grained data access policies on the real code

        bpf_trace_printk("Match limit exceeds threshold\\n");
        // Example policy: Check if the matching limit exceeds a threshold
        uint32_t limit_match;
        bpf_probe_read(&limit_match, sizeof(limit_match), &real_code->limit_match);
        if (limit_match < 10) {
            // Log an event or take appropriate action
            bpf_trace_printk("Match limit exceeds threshold\\n");
        }

        // Remove the real code data from the BPF map
        real_code_map.delete(&pid);
    }

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=ebpf_code)

# Attach the eBPF program to the PCRE2 functions
# b.attach_uretprobe(name="/usr/local/lib/libpcre2-8.so.0", sym="pcre2_compile_8", fn_name="pcre2_compile_entry")
b.attach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_match_8", fn_name="pcre2_match_entry")

# Print header
print("%-18s %-16s %-6s %s" % ("TIME", "COMM", "PID", "MESSAGE"))

# Read and print eBPF events
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except ValueError:
        continue
