#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Define the pcre2_real_code structure
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
    uint32_t limit_depth;
    uint32_t first_codeunit;
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

// Define the warning event structure
struct warning_event {
    u32 pid;
    u32 field_offset;
    char msg[64];
};

// Map to store the code parameter states
BPF_HASH(code_states, u64, struct pcre2_real_code);

// Perf event map for warning events
BPF_PERF_OUTPUT(warning_events);

// Entry function (uprobe)
int pcre2_match_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    // Get the code parameter from the function arguments
    const void *code = (const void *)PT_REGS_PARM1(ctx);

    // Read the code parameter fields
    struct pcre2_real_code entry_code = {};
    bpf_probe_read_kernel(&entry_code.magic_number, sizeof(entry_code.magic_number), &(((struct pcre2_real_code *)code)->magic_number));
    bpf_probe_read_kernel(&entry_code.compile_options, sizeof(entry_code.compile_options), &(((struct pcre2_real_code *)code)->compile_options));
    bpf_probe_read_kernel(&entry_code.overall_options, sizeof(entry_code.overall_options), &(((struct pcre2_real_code *)code)->overall_options));
    bpf_probe_read_kernel(&entry_code.extra_options, sizeof(entry_code.extra_options), &(((struct pcre2_real_code *)code)->extra_options));
    bpf_probe_read_kernel(&entry_code.flags, sizeof(entry_code.flags), &(((struct pcre2_real_code *)code)->flags));
    // Read more fields as needed

    // Store the code parameter states in the map
    code_states.update(&pid, &entry_code);

    return 0;
}

// Exit function (uretprobe)
int pcre2_match_exit(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();

    // Get the stored code parameter states from the map
    struct pcre2_real_code *entry_code = code_states.lookup(&pid);
    if (entry_code) {
        // Get the current code parameter from the function arguments
        const void *code = (const void *)PT_REGS_PARM1(ctx);

        // Read the current code parameter fields
        struct pcre2_real_code exit_code;
        bpf_probe_read_kernel(&exit_code.magic_number, sizeof(exit_code.magic_number), &(((struct pcre2_real_code *)code)->magic_number));
        bpf_probe_read_kernel(&exit_code.compile_options, sizeof(exit_code.compile_options), &(((struct pcre2_real_code *)code)->compile_options));
        bpf_probe_read_kernel(&exit_code.overall_options, sizeof(exit_code.overall_options), &(((struct pcre2_real_code *)code)->overall_options));
        bpf_probe_read_kernel(&exit_code.extra_options, sizeof(exit_code.extra_options), &(((struct pcre2_real_code *)code)->extra_options));
        bpf_probe_read_kernel(&exit_code.flags, sizeof(exit_code.flags), &(((struct pcre2_real_code *)code)->flags));
        // Read more fields as needed

        // Compare the current code parameter fields with the stored values
        if (entry_code->magic_number != exit_code.magic_number) {
            struct warning_event event = {
                .pid = pid >> 32,
                .field_offset = offsetof(struct pcre2_real_code, magic_number),
                .msg = "Field 'magic_number' has changed",
            };
            warning_events.perf_submit(ctx, &event, sizeof(event));
        }
        // ... (compare other fields and send warning events)

        // Remove the stored code parameter states from the map
        code_states.delete(&pid);
    }

    return 0;
}
