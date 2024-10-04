import os
import time
import random
import threading
from multiprocessing import Process
from typing import List, Callable, Union

class FunctionCaller:
    def __init__(self, name: str):
        self.name = name

    def method_1(self, duration_s: float) -> None:
        time.sleep(duration_s)


def grandchild_function(duration_s: float) -> None:
    time.sleep(duration_s)

def child_function(duration_s: float) -> None:
    grandchild_function(duration_s)
    time.sleep(duration_s)

def parent_function(duration_s: float) -> None:
    child_function(duration_s)
    time.sleep(duration_s)

def worker_thread(thread_id: int) -> None:
    function_caller = FunctionCaller(f"Thread {thread_id}")
    while True:
        choice: Callable[[float], None] = random.choice([parent_function, child_function, grandchild_function, function_caller.method_1])
        duration_s = 0.001 # 1ms
        choice(duration_s)
        time.sleep(random.uniform(0.01, 0.05))  # Small pause between function calls

def worker_process(process_id: int) -> None:
    threads: List[threading.Thread] = []
    for i in range(3):  # Create 3 threads per process
        t = threading.Thread(target=worker_thread, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def main() -> None:
    main_pid: int = os.getpid()
    
    processes: List[Process] = []
    for i in range(3):  # Create 3 processes
        p = Process(target=worker_process, args=(i,))
        processes.append(p)
        p.start()

    # Collect all PIDs
    pids: List[int] = [main_pid] + [p.pid for p in processes]
    
    # Print all PIDs once
    print("All Process IDs:")
    for pid in pids:
        print(f"PID: {pid}")

    for p in processes:
        p.join()

    print("All processes completed.")

if __name__ == "__main__":
    main()
