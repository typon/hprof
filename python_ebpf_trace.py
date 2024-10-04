import argparse
from bcc import BPF, USDT
import ctypes as ct
import time
from collections import defaultdict

# Argument parsing
examples = """examples:
    ./python_trace 185                # trace Python method calls in process 185
    ./python_trace -M indexOf 185     # trace only 'indexOf'-prefixed methods
    ./python_trace -C '<stdin>' 180   # trace only REPL-defined methods
"""
parser = argparse.ArgumentParser(
    description="Trace method execution flow in Python.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-M", "--method",
    help="trace only calls to methods starting with this prefix")
parser.add_argument("-C", "--class", dest="clazz",
    help="trace only calls to classes starting with this prefix")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# USDT context
usdt = USDT(pid=args.pid)

# BPF program
program = """
struct call_t {
    u64 depth;                  // first bit is direction (0 entry, 1 return)
    u64 pid;                    // (tgid << 32) + pid from bpf_get_current...
    char clazz[80];
    char method[80];
};

BPF_PERF_OUTPUT(calls);
BPF_HASH(entry, u64, u64);
"""

prefix_template = """
static inline bool prefix_%s(char *actual) {
    char expected[] = "%s";
    for (int i = 0; i < sizeof(expected) - 1; ++i) {
        if (expected[i] != actual[i]) {
            return false;
        }
    }
    return true;
}
"""

if args.clazz:
    program += prefix_template % ("class", args.clazz)
if args.method:
    program += prefix_template % ("method", args.method)

trace_template = """
int NAME(struct pt_regs *ctx) {
    u64 *depth, zero = 0, clazz = 0, method = 0 ;
    struct call_t data = {};

    READ_CLASS
    READ_METHOD
    bpf_probe_read_user(&data.clazz, sizeof(data.clazz), (void *)clazz);
    bpf_probe_read_user(&data.method, sizeof(data.method), (void *)method);

    FILTER_CLASS
    FILTER_METHOD

    data.pid = bpf_get_current_pid_tgid();
    depth = entry.lookup_or_try_init(&data.pid, &zero);
    if (!depth) {
        depth = &zero;
    }
    data.depth = DEPTH;
    UPDATE

    calls.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def enable_probe(probe_name: str, func_name: str, read_class: str, read_method: str, is_return: bool) -> None:
    global program, trace_template, usdt
    depth = "*depth + 1" if not is_return else "*depth | (1ULL << 63)"
    update = "++(*depth);" if not is_return else "if (*depth) --(*depth);"
    filter_class = "if (!prefix_class(data.clazz)) { return 0; }" \
                   if args.clazz else ""
    filter_method = "if (!prefix_method(data.method)) { return 0; }" \
                   if args.method else ""
    program += trace_template.replace("NAME", func_name)                \
                             .replace("READ_CLASS", read_class)         \
                             .replace("READ_METHOD", read_method)       \
                             .replace("FILTER_CLASS", filter_class)     \
                             .replace("FILTER_METHOD", filter_method)   \
                             .replace("DEPTH", depth)                   \
                             .replace("UPDATE", update)
    usdt.enable_probe_or_bail(probe_name, func_name)

enable_probe("function__entry", "python_entry",
             "bpf_usdt_readarg(1, ctx, &clazz);",   # filename really
             "bpf_usdt_readarg(2, ctx, &method);", is_return=False)
enable_probe("function__return", "python_return",
             "bpf_usdt_readarg(1, ctx, &clazz);",   # filename really
             "bpf_usdt_readarg(2, ctx, &method);", is_return=True)

if args.ebpf or args.verbose:
    if args.verbose:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt])
print(f"Profiling method calls in Python process {args.pid}... Ctrl-C to quit.")

class CallEvent(ct.Structure):
    _fields_ = [
        ("depth", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("clazz", ct.c_char * 80),
        ("method", ct.c_char * 80)
    ]

# Data structure to store profiling statistics
class FunctionStats:
    def __init__(self):
        self.count = 0
        self.total_time = 0.0
        self.min_time = float('inf')
        self.max_time = float('-inf')

    def update(self, duration):
        self.count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)

    def average_time(self):
        return self.total_time / self.count if self.count > 0 else 0.0

# Dictionary to store statistics for each method
function_stats = defaultdict(FunctionStats)

# Dictionary to store start times for each method call
start_times = {}

def print_event(cpu: int, data: ct.c_void_p, size: int) -> None:
    event = ct.cast(data, ct.POINTER(CallEvent)).contents
    depth_value = int(event.depth)
    direction = "<- " if depth_value & (1 << 63) else "-> "
    method_name = event.clazz.decode('utf-8', 'replace') + ":" + event.method.decode('utf-8', 'replace')

    current_time = time.time()

    if direction == "-> ":
        # Store the start time for the method call
        start_times[(event.pid, method_name)] = current_time
    elif direction == "<- ":
        # Calculate the duration and update statistics
        start_time = start_times.pop((event.pid, method_name), None)
        if start_time is not None:
            duration = current_time - start_time
            function_stats[method_name].update(duration)

bpf["calls"].open_perf_buffer(print_event)

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    # Print profiling statistics on exit
    print("\nProfiling statistics:")
    for method, stats in function_stats.items():
        print(f"{method}: count={stats.count}, avg={stats.average_time():.6f}s, "
              f"min={stats.min_time:.6f}s, max={stats.max_time:.6f}s")
    exit()