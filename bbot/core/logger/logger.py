import sys
import atexit
import logging
from copy import copy
from pathlib import Path
from queue import SimpleQueue
from contextlib import suppress
from logging.handlers import QueueHandler, QueueListener

from ..configurator import config
from ..helpers.misc import mkdir, error_and_exit


class ColoredFormatter(logging.Formatter):
    """
    Pretty colors for terminal
    """

    color_mapping = {
        "DEBUG": 242,  # grey
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

    char_mapping = {
        "DEBUG": "DBUG",
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

    prefix = "\033[1;38;5;"
    suffix = "\033[0m"

    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, "INFO")
        seq = self.color_mapping.get(levelname, 15)  # default white
        colored_levelname = f"{self.prefix}{seq}m[{levelchar}]{self.suffix}"
        if levelname == "CRITICAL" or levelname.startswith("HUGE"):
            colored_record.msg = f"{self.prefix}{seq}m{colored_record.msg}{self.suffix}"
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)


def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel('TRACE')
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
        raise AttributeError("{} already defined in logging module".format(levelName))
    if hasattr(logging, methodName):
        raise AttributeError("{} already defined in logging module".format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
        raise AttributeError("{} already defined in logger class".format(methodName))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)

    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)


# custom logging levels
addLoggingLevel("STDOUT", 100)
addLoggingLevel("HUGEWARNING", 31)
addLoggingLevel("HUGESUCCESS", 26)
addLoggingLevel("SUCCESS", 25)
addLoggingLevel("HUGEINFO", 21)
addLoggingLevel("HUGEVERBOSE", 16)
addLoggingLevel("VERBOSE", 15)


def stop_listener(listener):
    with suppress(Exception):
        listener.stop()


def log_worker_setup(logging_queue):
    """
    This needs to be run whenever a new multiprocessing.Process() is spawned
    """
    log_level = get_log_level()
    log = logging.getLogger("bbot")
    # Don't do this more than once
    if len(log.handlers) == 0:
        log.setLevel(log_level)
        queue_handler = QueueHandler(logging_queue)
        log.addHandler(queue_handler)
    return log


def log_listener_setup(logging_queue):

    log_dir = Path(config["home"]) / "logs"
    if not mkdir(log_dir, raise_error=False):
        error_and_exit(f"Failure creating or error writing to BBOT logs directory ({log_dir})")

    # Log to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)

    # Log to stdout
    stdout_handler = logging.StreamHandler(sys.stdout)

    # Main log file
    main_handler = logging.handlers.TimedRotatingFileHandler(
        f"{log_dir}/bbot.log", when="d", interval=1, backupCount=14
    )

    # Separate log file for debugging
    debug_handler = logging.handlers.TimedRotatingFileHandler(
        f"{log_dir}/bbot.debug.log", when="d", interval=1, backupCount=14
    )

    log_level = get_log_level()

    stderr_handler.addFilter(lambda x: x.levelno != logging.STDOUT and x.levelno >= log_level)
    stdout_handler.addFilter(lambda x: x.levelno == logging.STDOUT)
    debug_handler.addFilter(lambda x: x.levelno != logging.STDOUT and x.levelno >= logging.DEBUG)
    main_handler.addFilter(lambda x: x.levelno != logging.STDOUT and x.levelno >= logging.VERBOSE)

    # Set log format
    debug_format = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)s %(message)s")
    debug_handler.setFormatter(debug_format)
    main_handler.setFormatter(debug_format)
    stderr_handler.setFormatter(ColoredFormatter("%(levelname)s %(name)s: %(message)s"))
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))

    handlers = [stdout_handler, stderr_handler, main_handler]
    if config.get("debug", False):
        handlers.append(debug_handler)

    log_listener = QueueListener(logging_queue, *handlers)
    log_listener.start()
    atexit.register(stop_listener, log_listener)
    return {
        "stderr": stderr_handler,
        "stdout": stdout_handler,
        "file_debug": debug_handler,
        "file_main": main_handler,
    }


def init_logging():
    """
    Initializes logging, returns logging queue and dictionary containing log handlers
    """

    handlers = {}
    logging_queue = None

    log = logging.getLogger("bbot")
    # Don't do this more than once
    if len(log.handlers) == 0:
        logging_queue = SimpleQueue()
        handlers = log_listener_setup(logging_queue)
        log_worker_setup(logging_queue)

    return logging_queue, handlers


def get_log_level():
    from bbot.core.configurator.args import cli_options

    loglevel = logging.INFO
    if cli_options is not None:
        if cli_options.verbose:
            loglevel = logging.VERBOSE
        if cli_options.debug:
            loglevel = logging.DEBUG
    return loglevel
