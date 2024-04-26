import sys
import multiprocessing as mp

try:
    mp.set_start_method("spawn")
except Exception:
    start_method = mp.get_start_method()
    if start_method != "spawn":
        print(
            f"[WARN] Multiprocessing spawn method is set to {start_method}. This may negatively affect performance.",
            file=sys.stderr,
        )
