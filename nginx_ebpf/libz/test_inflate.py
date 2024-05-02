from bcc import BPF
from time import sleep

# Load the eBPF program
b = BPF(src_file="inflate_monitor.c")
b.attach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="inflate", fn_name="inflate_entry")

print("Monitoring 'inflate' function in libz...")

try:
    while True:
        sleep(1)
        print("Inflate function call counts:")
        for k, v in b["inflate_stats"].items():
            print(f"PID {k.value}: {v.value} calls")
except KeyboardInterrupt:
    print("Exiting...")

b.detach_uprobe(name="/lib/x86_64-linux-gnu/libz.so.1", sym="inflate")
