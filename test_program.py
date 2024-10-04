import os
import sys
import time
from tqdm import tqdm

def foo():
    time.sleep(0.1)
    return 1 + 1

def bar():
    time.sleep(0.01)
    return foo() * 2

def main():
    # Print the current process ID
    pid = os.getpid()
    print(f"Process ID (PID): {pid}")

    # Initialize the tqdm progress bar with a spinner format
    with tqdm(
        desc="Processing",
        bar_format="{desc} |{bar}| {elapsed} elapsed",
        total=None,          # No predefined total for an unlimited spinner
        dynamic_ncols=True,  # Adjust the progress bar width dynamically
        ascii=False,         # Use Unicode characters for the spinner
        ncols=80,            # Set a default width (optional)
    ) as spinner:
        try:
            while True:
                # Update the progress bar by 1 step
                spinner.update(1)
                # Sleep for a short duration to control spinner speed
                bar()
                foo()
        except KeyboardInterrupt:
            # Handle user interruption (e.g., Ctrl+C)
            spinner.close()
            print("\nSpinner stopped by user.")

if __name__ == "__main__":
    print(f"Test program PID: {os.getpid()}")
    count = 0
    while True:
        bar()
        foo()
        count += 1
        if count % 100000 == 0:
            print(f"Executed {count} iterations")

