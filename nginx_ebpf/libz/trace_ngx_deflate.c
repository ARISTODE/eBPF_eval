#include <uapi/linux/ptrace.h>

int ngx_http_gzip_filter_deflate_start(struct pt_regs *ctx) {
    bpf_trace_printk("ngx_http_gzip_filter_deflate function called\\n");
    return 0;
}
