import os
import sys
import logging.handlers

loglevel_mapping = {
    "DEBUG": "DBUG",
    "TRACE": "TRCE",
    "VERBOSE": "VERB",
    "HUGEVERBOSE": "VERB",
    "INFO": "INFO",
    "HUGEINFO": "INFO",
    "SUCCESS": "SUCC",
    "HUGESUCCESS": "SUCC",
    "WARNING": "WARN",
    "HUGEWARNING": "WARN",
    "ERROR": "ERRR",
    "CRITICAL": "CRIT",
}
color_mapping = {
    "DEBUG": 242,  # grey
    "TRACE": 242,  # red
    "VERBOSE": 242,  # grey
    "INFO": 69,  # blue
    "HUGEINFO": 69,  # blue
    "SUCCESS": 118,  # green
    "HUGESUCCESS": 118,  # green
    "WARNING": 208,  # orange
    "HUGEWARNING": 208,  # orange
    "ERROR": 196,  # red
    "CRITICAL": 196,  # red
}
color_prefix = "\033[1;38;5;"
color_suffix = "\033[0m"


def colorize(s, level="INFO"):
    seq = color_mapping.get(level, 15)  # default white
    colored = f"{color_prefix}{seq}m{s}{color_suffix}"
    return colored


def log_to_stderr(msg, level="INFO", logname=True):
    """
    Print to stderr with BBOT logger colors
    """
    levelname = level.upper()
    if not any(x in sys.argv for x in ("-s", "--silent")):
        levelshort = f"[{loglevel_mapping.get(level, 'INFO')}]"
        levelshort = f"{colorize(levelshort, level=levelname)}"
        if levelname == "CRITICAL" or levelname.startswith("HUGE"):
            msg = colorize(msg, level=levelname)
        if logname:
            msg = f"{levelshort} {msg}"
        print(msg, file=sys.stderr)


class GzipRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    A rotating file handler that compresses rotated files with gzip.
    Checks file size only periodically to improve performance.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._msg_count = 0
        self._check_interval = 1000  # Check size every 1000 messages

    def rotation_filename(self, default_name):
        """
        Modify the rotated filename to include .gz extension
        """
        return default_name + ".gz"

    def rotate(self, source, dest):
        """
        Compress the source file and move it to the destination.
        """
        import gzip

        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                f_out.writelines(f_in)
        os.remove(source)

    def emit(self, record):
        """
        Emit a record, checking for rollover only periodically using modulo.
        """
        self._msg_count += 1

        # Only check for rollover periodically to save compute
        if self._msg_count % self._check_interval == 0:
            if self.shouldRollover(record):
                self.doRollover()

        # Continue with normal emit process
        super().emit(record)
