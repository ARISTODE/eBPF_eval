from bcc import BPF

# Load the eBPF program
bpf = BPF(src_file="trace_ngx_deflate.c")

# Attach the tracing probe to the ngx_http_gzip_filter_deflate function
bpf.attach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="ngx_http_gzip_body_filter", fn_name="ngx_http_gzip_filter_deflate_start")

# Print the traced events
print("Tracing ngx_http_gzip_filter_deflate function... Hit Ctrl-C to end.")
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print(msg)
    except KeyboardInterrupt:
        exit()
