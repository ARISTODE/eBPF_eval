from bcc import BPF
import ctypes as ct

# Define the warning event structure
class WarningEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("field_offset", ct.c_uint32),
        ("msg", ct.c_char * 64),
    ]

# Read the eBPF program from the file
with open("test_pcre_match.c", "r") as f:
    ebpf_program = f.read()

# Load the eBPF program
b = BPF(text=ebpf_program)

# Attach the uprobes and uretprobes to the pcre2_match function
try:
    b.attach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_match_8", fn_name="pcre2_match_entry")
    b.attach_uretprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_match_8", fn_name="pcre2_match_exit")
    print("Successfully attached to nginx, pcre2_match_8\n")

except Exception as e:
    print(f"Failed to attach eBPF program to the target executable: {target_executable}")
    print(str(e))
    sys.exit(1)

# Define the warning event callback
def warning_event_callback(cpu, data, size):
    event = ct.cast(data, ct.POINTER(WarningEvent)).contents
    print(f"Warning: {event.msg.decode()} (PID: {event.pid}, Field Offset: {event.field_offset})")

# Set up the perf event buffer
b["warning_events"].open_perf_buffer(warning_event_callback)

# Start the perf event loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

# Detach the uprobes and uretprobes
b.detach_uprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_match_8")
b.detach_uretprobe(name="/home/yzh89/Documents/eBPF_eval/nginx-1.22.1/objs/nginx", sym="pcre2_match_8")
