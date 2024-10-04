# Python profiler using eBPF

# Prerequisites

### Install bcc tools

```
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) libbpf-dev
```

### Make venv using uv

```
 uv venv --system-site-packages --python /usr/bin/python3
```

You need to do this because bcc python library is installed inside the system site packages
and not available as a pypi package.

# Install 
