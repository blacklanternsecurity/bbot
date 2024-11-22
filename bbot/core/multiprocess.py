import os
import atexit
from contextlib import suppress


class SharedInterpreterState:
    """
    A class to track the primary BBOT process.

    Used to prevent spawning multiple unwanted processes with multiprocessing.
    """

    def __init__(self):
        self.main_process_var_name = "_BBOT_MAIN_PID"
        self.scan_process_var_name = "_BBOT_SCAN_PID"
        atexit.register(self.cleanup)

    @property
    def is_main_process(self):
        is_main_process = self.main_pid == os.getpid()
        return is_main_process

    @property
    def is_scan_process(self):
        is_scan_process = os.getpid() == self.scan_pid
        return is_scan_process

    @property
    def main_pid(self):
        main_pid = int(os.environ.get(self.main_process_var_name, 0))
        if main_pid == 0:
            main_pid = os.getpid()
            # if main PID is not set, set it to the current PID
            os.environ[self.main_process_var_name] = str(main_pid)
        return main_pid

    @property
    def scan_pid(self):
        scan_pid = int(os.environ.get(self.scan_process_var_name, 0))
        if scan_pid == 0:
            scan_pid = os.getpid()
            # if scan PID is not set, set it to the current PID
            os.environ[self.scan_process_var_name] = str(scan_pid)
        return scan_pid

    def update_scan_pid(self):
        os.environ[self.scan_process_var_name] = str(os.getpid())

    def cleanup(self):
        with suppress(Exception):
            if self.is_main_process:
                with suppress(KeyError):
                    del os.environ[self.main_process_var_name]
                with suppress(KeyError):
                    del os.environ[self.scan_process_var_name]


SHARED_INTERPRETER_STATE = SharedInterpreterState()
