from bcc import BPF
from time import sleep

# Load the eBPF program
b = BPF(src_file="test_pcre_compile.c")
b.attach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_compile_8", fn_name="pcre2_compile_entry")

print("Monitoring 'pcre2_compile' function...")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")

b.detach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_compile_8")
