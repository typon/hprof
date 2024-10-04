from bcc import BPF
import ctypes as ct

# BPF program
bpf_source = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_python_execution(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_source)

library_path = "/usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0"
function_name = "_PyObject_Call"

print(f"Attaching to library: {library_path}")
print(f"Tracing function: {function_name}")

# Attach to PyObject_Call
try:
    b.attach_uprobe(name=library_path, sym=function_name, fn_name="trace_python_execution")
    print("Uprobe attached successfully")
except Exception as e:
    print(f"Error attaching probe: {e}")
    exit(1)

# Process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, Comm: {event.comm.decode('utf-8')}, Time: {event.ts}")

# Loop with callback to print_event
b["events"].open_perf_buffer(print_event)
print("Tracing... Ctrl-C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
