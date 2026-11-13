import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from bbot.test.worker import (
    BASE_BBOT_TEST_DIR,
    BBOT_TEST_SHARED_DIR,
    RUN_ID,
    WORKER_PORT_STRIDE,
    _worker_index,
    remove_stale_test_dirs,
    worker_dir,
    worker_id,
    worker_port,
)


def _env(value):
    if value is None:
        return patch.dict("os.environ", {}, clear=True)
    return patch.dict("os.environ", {"PYTEST_XDIST_WORKER": value})


def test_worker_id_serial_is_empty():
    with _env(None):
        assert worker_id() == ""


def test_worker_id_recognizes_gw_workers():
    for name in ("gw0", "gw1", "gw15"):
        with _env(name):
            assert worker_id() == name


def test_worker_id_rejects_non_gw_values():
    for name in ("master", "", "controller"):
        with _env(name):
            assert worker_id() == ""


def test_worker_index_parses_the_number():
    for name, expected in (("gw0", 0), ("gw1", 1), ("gw15", 15)):
        with _env(name):
            assert _worker_index() == expected


def test_worker_index_defaults_to_zero():
    with _env(None):
        assert _worker_index() == 0
    with _env("gwX"):
        assert _worker_index() == 0


def test_worker_port_is_unchanged_when_serial():
    with _env(None):
        assert worker_port(8888) == 8888


def test_worker_port_blocks_do_not_overlap():
    bases = [8888, 9999, 5556, 8978, 8765]
    seen = {}
    for i in range(16):
        with _env(f"gw{i}"):
            for base in bases:
                port = worker_port(base)
                assert port not in seen, f"port {port} collides: gw{i}/{base} vs {seen[port]}"
                seen[port] = f"gw{i}/{base}"


def test_worker_port_uses_the_stride():
    with _env("gw3"):
        assert worker_port(8888) == 8888 + 3 * WORKER_PORT_STRIDE


def test_worker_dir_is_unchanged_when_serial():
    with _env(None):
        assert worker_dir() == BASE_BBOT_TEST_DIR
        assert worker_dir("/tmp/.bbot_example") == Path("/tmp/.bbot_example")


def test_worker_dir_is_unique_per_worker():
    seen = set()
    for i in range(16):
        with _env(f"gw{i}"):
            d = worker_dir()
            assert d not in seen
            seen.add(d)
    with _env("gw2"):
        assert worker_dir("/tmp/.bbot_example") == Path("/tmp/.bbot_example_gw2")


def test_dirs_are_unique_to_the_run():
    # xdist workers inherit the controller's run id, so a run's processes share it and no other run does
    assert os.environ["BBOT_TEST_RUN_ID"] == RUN_ID
    assert BASE_BBOT_TEST_DIR.name == f".bbot_test_{RUN_ID}"
    assert BBOT_TEST_SHARED_DIR.name == f".bbot_test_{RUN_ID}_shared"


def test_remove_stale_test_dirs(tmp_path):
    exited = subprocess.Popen(["true"])
    exited.wait()
    dead, alive = exited.pid, os.getpid()
    stale = [f".bbot_test_{dead}", f".bbot_test_{dead}_gw3", f".bbot_test_{dead}_shared"]
    # a running test run's, and the fixed paths an older checkout may be using right now
    kept = [f".bbot_test_{alive}", f".bbot_test_{alive}_shared", ".bbot_test", ".bbot_test_shared", ".bbot_test_gw0"]
    for name in stale + kept:
        (tmp_path / name / "cache").mkdir(parents=True)

    remove_stale_test_dirs(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(kept)
