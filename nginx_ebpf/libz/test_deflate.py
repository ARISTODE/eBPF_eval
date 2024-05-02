from bcc import BPF

# BPF program
bpf_code = '''
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>


struct z_stream_s {
    const unsigned char *next_in;   /* next input byte */
    unsigned int avail_in;          /* number of bytes available at next_in */
    unsigned long total_in;         /* total number of input bytes read so far */
    unsigned char *next_out;        /* next output byte will go here */
    unsigned int avail_out;         /* remaining free space at next_out */
    unsigned long total_out;        /* total number of bytes output so far */
    const char *msg;        /* last error message, NULL if no error */
    void *state; /* not visible by applications */
    void* zalloc;      /* used to allocate the internal state */
    void* zfree;       /* used to free the internal state */
    void* opaque;          /* private data object passed to zalloc and zfree */
    int data_type;          /* best guess about the data type: binary or text
                               for deflate, or the decoding state for inflate */
    unsigned long adler;            /* Adler-32 or CRC-32 value of the uncompressed data */
    unsigned long reserved;         /* reserved for future use */
};

struct z_stream_entry {
    struct z_stream_s strm;
};

struct z_stream_exit {
    struct z_stream_s strm;
};

BPF_HASH(entry_map, u32, struct z_stream_entry);
BPF_HASH(exit_map, u32, struct z_stream_exit);

int deflate_entry(struct pt_regs *ctx) {
    struct z_stream_s *strm = (struct z_stream_s *)PT_REGS_PARM1(ctx);
    u32 tid = bpf_get_current_pid_tgid();
    bpf_trace_printk("state field modified\\n");
    struct z_stream_entry entry = {};
    bpf_probe_read(&entry.strm, sizeof(entry.strm), strm);
    entry_map.update(&tid, &entry);
    return 0;
}

int deflate_exit(struct pt_regs *ctx) {
    struct z_stream_s *strm = (struct z_stream_s *)PT_REGS_PARM1(ctx);
    u32 tid = bpf_get_current_pid_tgid();

    struct z_stream_entry *entryp = entry_map.lookup(&tid);
    if (!entryp) {
        return 0;
    }

    struct z_stream_exit exit = {};
    bpf_probe_read(&exit.strm, sizeof(exit.strm), strm);
    exit_map.update(&tid, &exit);

    // Compare the fields of strm at entry and exit
    if (entryp->strm.next_in != exit.strm.next_in) {
        // Raise an alert or log the violation
        bpf_trace_printk("next_in field modified\\n");
    }
    if (entryp->strm.msg != exit.strm.msg) {
        // Raise an alert or log the violation
        bpf_trace_printk("msg field modified\\n");
    }
    if (entryp->strm.state != exit.strm.state) {
        // Raise an alert or log the violation
        bpf_trace_printk("state field modified\\n");
    }
    if (entryp->strm.zalloc != exit.strm.zalloc) {
        // Raise an alert or log the violation
        bpf_trace_printk("zalloc field modified\\n");
    }
    if (entryp->strm.zfree != exit.strm.zfree) {
        // Raise an alert or log the violation
        bpf_trace_printk("zfree field modified\\n");
    }
    if (entryp->strm.opaque != exit.strm.opaque) {
        // Raise an alert or log the violation
        bpf_trace_printk("opaque field modified\\n");
    }
    if (entryp->strm.reserved != exit.strm.reserved) {
        // Raise an alert or log the violation
        bpf_trace_printk("reserved field modified\\n");
    }

    entry_map.delete(&tid);
    exit_map.delete(&tid);

    return 0;
}
'''

# Load the BPF program
b = BPF(text=bpf_code)

# Attach the entry and exit probes to the deflate function

b.attach_uprobe(name='/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx', sym="deflate", fn_name='deflate_entry')
b.attach_uretprobe(name='/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx', sym="deflate", fn_name='deflate_exit')

# Print the output of the BPF program
print('Tracing deflate() function...')
print('Hit Ctrl-C to end.')

# Read and print the trace output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f'[{ts}] {msg}')
    except KeyboardInterrupt:
        print('Exiting.')
        break

# Detach the probes
b.detach_uprobe(name='/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx', sym="deflate")
b.detach_uretprobe(name='/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx', sym="deflate") 
