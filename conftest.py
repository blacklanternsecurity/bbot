# The xdist controller loads this file whatever path pytest is given. It only loads
# bbot/test/conftest.py for a path at or below bbot/, and not for CI's `pytest -n N .`,
# so the run id (set when bbot.test.worker is imported) and the controller-only
# cleanup are here, before any worker starts.
import shutil

from bbot.test.worker import BBOT_TEST_SHARED_DIR, remove_stale_test_dirs, worker_id


def pytest_sessionstart(session):
    if not worker_id():
        remove_stale_test_dirs()


def pytest_sessionfinish(session, exitstatus):
    # the xdist controller finishes last, after every worker is done with the shared deps
    if not worker_id():
        shutil.rmtree(BBOT_TEST_SHARED_DIR, ignore_errors=True)
