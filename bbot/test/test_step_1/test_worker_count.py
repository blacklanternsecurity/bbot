from unittest.mock import patch

from bbot.test.worker_count import RESERVE_MB, MB_PER_WORKER, cpu_count, worker_count


def _sysconf(total_mb):
    def inner(name):
        if name == "SC_PAGE_SIZE":
            return 4096
        if name == "SC_PHYS_PAGES":
            return total_mb * 1024 * 1024 // 4096
        raise ValueError(name)

    return inner


def test_worker_count_env_override_wins():
    with patch.dict("os.environ", {"BBOT_TEST_WORKERS": "3"}):
        assert worker_count() == 3
    with patch.dict("os.environ", {"BBOT_TEST_WORKERS": "999"}):
        assert worker_count() == 999


def test_worker_count_env_override_is_sanitized():
    with patch.dict("os.environ", {"BBOT_TEST_WORKERS": "  4  "}):
        assert worker_count() == 4
    for bogus in ("0", "-1"):
        with patch.dict("os.environ", {"BBOT_TEST_WORKERS": bogus}):
            assert worker_count() == 1


def test_worker_count_ignores_blank_override():
    with patch.dict("os.environ", {"BBOT_TEST_WORKERS": "   "}):
        with patch("bbot.test.worker_count.cpu_count", return_value=4):
            with patch("os.sysconf", _sysconf(RESERVE_MB + 4 * MB_PER_WORKER)):
                assert worker_count() == 4


def test_worker_count_is_capped_by_memory():
    total = RESERVE_MB + 2 * MB_PER_WORKER
    with patch.dict("os.environ", {}, clear=True):
        with patch("bbot.test.worker_count.cpu_count", return_value=64):
            with patch("os.sysconf", _sysconf(total)):
                assert worker_count() == 2


def test_worker_count_is_capped_by_cores():
    with patch.dict("os.environ", {}, clear=True):
        with patch("bbot.test.worker_count.cpu_count", return_value=4):
            with patch("os.sysconf", _sysconf(RESERVE_MB + 64 * MB_PER_WORKER)):
                assert worker_count() == 4


def test_worker_count_never_returns_zero_on_small_machines():
    with patch.dict("os.environ", {}, clear=True):
        with patch("bbot.test.worker_count.cpu_count", return_value=8):
            for total in (RESERVE_MB // 2, RESERVE_MB, RESERVE_MB + 1):
                with patch("os.sysconf", _sysconf(total)):
                    assert worker_count() == 1


def test_worker_count_falls_back_to_cpus_when_memory_unknown():
    for exc in (ValueError, OSError, AttributeError):
        with patch.dict("os.environ", {}, clear=True):
            with patch("bbot.test.worker_count.cpu_count", return_value=6):
                with patch("os.sysconf", side_effect=exc):
                    assert worker_count() == 6


def test_cpu_count_prefers_affinity():
    with patch("os.sched_getaffinity", return_value={0, 1}):
        assert cpu_count() == 2


def test_cpu_count_falls_back_without_affinity():
    with patch("os.sched_getaffinity", side_effect=AttributeError):
        with patch("os.cpu_count", return_value=12):
            assert cpu_count() == 12
    with patch("os.sched_getaffinity", side_effect=AttributeError):
        with patch("os.cpu_count", return_value=None):
            assert cpu_count() == 1
