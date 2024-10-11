import ctypes
import re
import argparse
import json
import os
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

import psutil
from bcc import BPF, USDT

MAX_STACK_DEPTH = 5
MAX_FUNC_NAME_LEN = 64


# Define the C struct in Python
class FunctionTraceEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("pid", ctypes.c_ulonglong),
        ("tid", ctypes.c_ulonglong),
        ("depth", ctypes.c_ulonglong),
        ("is_return", ctypes.c_ulonglong),
        ("file_name", ctypes.c_char * MAX_FUNC_NAME_LEN),
        ("func_name", ctypes.c_char * MAX_FUNC_NAME_LEN),
        ("lineno", ctypes.c_int),
    ]


class CompletedStackEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("pid", ctypes.c_ulonglong),
        ("tid", ctypes.c_ulonglong),
        ("duration", ctypes.c_ulonglong),
        ("depth", ctypes.c_ulonglong),
        ("entry_lineno", ctypes.c_int),
        ("return_lineno", ctypes.c_int),
        ("file_name", ctypes.c_char * MAX_FUNC_NAME_LEN),
        ("func_name", ctypes.c_char * MAX_FUNC_NAME_LEN),
        ("func_names", (ctypes.c_char * MAX_FUNC_NAME_LEN) * MAX_STACK_DEPTH),
    ]

    @property
    def file_name_parsed(self) -> str:
        full_file_name = Path(
            ctypes.string_at(self.file_name).decode("utf-8", "replace").strip()
        )
        return full_file_name.name

    @property
    def func_name_parsed(self) -> str:
        return ctypes.string_at(self.func_name).decode("utf-8", "replace").strip()

    @property
    def ts_us(self) -> int:
        return self.ts // 1000

    @property
    def duration_us(self) -> int:
        return self.duration // 1000

    @property
    def tid_short(self) -> int:
        return self.tid & 0xFFFF

    @property
    def func_names_parsed(self) -> list[str]:
        func_names = []
        func_names_raw = self.func_names
        for i in range(self.depth):
            name = (
                ctypes.string_at(func_names_raw[i]).decode("utf-8", "replace").strip()
            )
            assert (
                len(name) != 0
            ), f"Name is empty - depth: {self.depth}, func names: {self.func_names}"
            func_names.append(name)
        return func_names

    def __str__(self):
        return (
            f"CompletedStackEvent(ts={self.ts}, pid={self.pid}, tid={self.tid}, "
            f"duration(us)={self.duration / 1e3}, depth={self.depth}, func_name={self.func_name}, func_names={self.func_names_parsed})"
        )


@dataclass
class TraceEvent:
    """
    Trace event as defined by the Chrome Trace Event Format.
    For more information, see: https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview?tab=t.0
    """

    ts: int
    pid: int
    tid: int
    duration: int
    name: str
    stack: list[str]

    def serialize_to_chrome_trace_event(self) -> dict:
        return {
            "name": self.name,
            "cat": "python",
            "ph": "X",
            "ts": self.ts,
            "dur": self.duration,
            "pid": self.pid,
            "tid": self.tid,
            "stack": self.stack,
        }


class ProfilerState:
    """
    Example data in the emitted .json file for Chrome Trace Events.
    We will be using Completed events, rather than B/E events.
    We will also be storing the stack frame for each call.

    {
    traceEvents: [
        {"name": "myFunction", "cat": "foo", "ph": "X", "ts": 123, "dur": 234, "pid": 2343, "tid": 2347, "stack": [5, 7, 9]}
        ...
    ],
    }
    """

    def __init__(self) -> None:
        self.completed_trace_events: list[TraceEvent] = []

    def completed_stack_callback(self, cpu, data, size) -> None:
        event = ctypes.cast(data, ctypes.POINTER(CompletedStackEvent)).contents
        trace_event = TraceEvent(
            ts=event.ts_us,
            pid=event.pid,
            tid=event.tid_short,
            duration=event.duration_us,
            name=f"{event.file_name_parsed}:{event.entry_lineno}-{event.return_lineno}:{event.func_name_parsed}",
            stack=event.func_names_parsed,
        )
        self.completed_trace_events.append(trace_event)

    def write_trace_events_to_file(self, file_path: str) -> None:
        with open(file_path, "w") as f:
            json.dump(
                {
                    "traceEvents": [
                        event.serialize_to_chrome_trace_event()
                        for event in self.completed_trace_events
                    ]
                },
                f,
                indent=4,
            )


@dataclass
class ProfilerConfig:
    pids: list[int]
    process_name_regex: str

    def __post_init__(self):
        if self.pids is None:
            self.pids = self.get_python_pids()
            if len(self.pids) == 0:
                raise ValueError(
                    f"No valid Python processes found matching the provided regex pattern: {self.process_name_regex}"
                )

    def get_python_pids(self) -> list[int]:
        """
        Get all running process executable names that match the regex pattern.
        """
        assert (
            self.process_name_regex is not None
        ), "process_name_regex must be provided if pids are not provided"

        pids = []
        for proc in psutil.process_iter(["name", "exe", "cmdline"]):
            exe = proc.info["exe"]
            # exe should contain "python"
            if "python" not in exe.lower():
                continue
            try:
                # Filter out the current process
                if proc.pid == os.getpid():
                    continue
                # Check if the cmdline contains the regex pattern
                if re.search(self.process_name_regex, " ".join(proc.info["cmdline"])):
                    pids.append(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return pids


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace method execution flow in multiple Python processes."
    )
    parser.add_argument(
        "--pids", type=int, nargs="*", help="process ids to attach to (optional)"
    )
    parser.add_argument(
        "--process-name",
        type=str,
        help="regex pattern to match process names (used if --pids is not provided)",
    )
    parser.add_argument(
        "--trace-file",
        type=str,
        default=f"trace_events_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json",
        help="file to write trace events to",
    )

    args = parser.parse_args()

    if args.pids is None and args.process_name is None:
        raise ValueError("Either --pids or --process-name must be provided")

    return args


def main():
    # Argument parsing
    args = parse_args()
    config = ProfilerConfig(pids=args.pids, process_name_regex=args.process_name)

    print(f"Profiling processes: {config.pids}")

    # Create USDT contexts for each PID
    usdt_contexts = [USDT(pid=pid) for pid in config.pids]

    # Attach USDT probes for each context
    for usdt in usdt_contexts:
        usdt.enable_probe(probe="function__entry", fn_name="trace_entry")
        usdt.enable_probe(probe="function__return", fn_name="trace_return")

    # Load BPF program
    current_dir = Path(__file__).parent
    bpf_program_path = current_dir / "bpf_program.c"
    with open(bpf_program_path, "r") as f:
        bpf_text = f.read()

    bpf = BPF(
        text=bpf_text,
        usdt_contexts=usdt_contexts,
        cflags=["-I/usr/include", "-Wno-everything"],
    )

    # Initialize data structures for profiling
    profiler_state = ProfilerState()

    # Attach the event handler
    bpf["completed_stacks"].open_perf_buffer(profiler_state.completed_stack_callback)
    print(f"Profiling method calls in Python processes {config.pids}... Ctrl-C to stop.")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        # Optionally handle graceful shutdown and data persistence
        profiler_state.write_trace_events_to_file(args.trace_file)
        print(
            f"\nProfiling stopped. {len(profiler_state.completed_trace_events)} trace events have been written to {args.trace_file}"
        )


if __name__ == "__main__":
    main()
