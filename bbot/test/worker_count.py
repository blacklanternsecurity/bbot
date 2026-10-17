#!/usr/bin/env python3
"""Print the number of pytest-xdist workers to use.

Bounded by cores *and* memory. `-n logical` is wrong on a box with many cores
relative to RAM: each worker holds roughly 700MB once warm, and elasticsearch
wants ~2GB on top, so a 16-core/16GB machine running 16 workers gets its
container OOM-killed (exit 137) and takes the run down with it.

Override with BBOT_TEST_WORKERS=<n>.
"""

import os

MB_PER_WORKER = 700
# Docker-backed services (elasticsearch ~2GB), the daemon, and the pytest parent.
RESERVE_MB = 5120


def cpu_count():
    # sched_getaffinity respects cgroup/taskset limits; os.cpu_count() does not.
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def worker_count():
    pinned = os.environ.get("BBOT_TEST_WORKERS", "").strip()
    if pinned:
        return max(1, int(pinned))
    try:
        total_mb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)
    except (ValueError, OSError, AttributeError):
        return cpu_count()
    return max(1, min(cpu_count(), (total_mb - RESERVE_MB) // MB_PER_WORKER))


if __name__ == "__main__":
    print(worker_count())
