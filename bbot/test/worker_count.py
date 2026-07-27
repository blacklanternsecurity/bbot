#!/usr/bin/env python3
"""Print the number of pytest-xdist workers to use.

`-n logical` is wrong on machines with many cores relative to RAM. Each worker
holds roughly 600MB once the suite is warm, and the docker-backed tests
(elasticsearch in particular) need a couple of GB of headroom on top. A 16-core
/ 16GB box running 16 workers leaves too little for elasticsearch, which then
gets OOM-killed with exit code 137 and takes the run down with it.

So: bounded by cores, but also by memory, keeping a reserve free.

Override with BBOT_TEST_WORKERS=<n> to pin an exact count.
"""

import os
import sys

# Rough steady-state resident size of one worker running this suite.
MB_PER_WORKER = 700

# Kept free for docker-backed services (elasticsearch wants ~2GB) plus the
# OS, the docker daemon and the pytest parent process.
RESERVE_MB = 5120

MIN_WORKERS = 2


def total_memory_mb():
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)
    except (ValueError, OSError, AttributeError):
        return None


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

    cores = cpu_count()
    total_mb = total_memory_mb()
    if not total_mb:
        return cores

    by_memory = (total_mb - RESERVE_MB) // MB_PER_WORKER
    return max(MIN_WORKERS, min(cores, by_memory))


if __name__ == "__main__":
    n = worker_count()
    if "-v" in sys.argv:
        print(
            f"cores={cpu_count()} total_mem={total_memory_mb()}MB reserve={RESERVE_MB}MB -> {n} workers",
            file=sys.stderr,
        )
    print(n)
