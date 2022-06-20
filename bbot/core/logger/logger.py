import sys
import atexit
import logging
from copy import copy
from pathlib import Path
from contextlib import suppress
from multiprocessing import Queue
from logging.handlers import QueueHandler, QueueListener


class ColoredFormatter(logging.Formatter):
    """
    Pretty colors for terminal
    """

    color_mapping = {
        "DEBUG": 242,  # grey
        "VERBOSE": 242,  # grey
        "INFO": 69,  # blue
        "SUCCESS": 118,  # green
        "WARNING": 208,  # orange
        "ERROR": 196,  # red
        "CRITICAL": 196,  # red
    }

    char_mapping = {
        "DEBUG": "DBUG",
        "VERBOSE": "VERB",
        "INFO": "INFO",
        "SUCCESS": "SUCC",
        "WARNING": "WARN",
        "ERROR": "ERRR",
        "CRITICAL": "CRIT",
    }

    prefix = "\033[1;38;5;"
    suffix = "\033[0m"

    def __init__(self, pattern):

        super().__init__(pattern)

    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, "INFO")
        seq = self.color_mapping.get(levelname, 15)  # default white
        colored_levelname = f"{self.prefix}{seq}m[{levelchar}]{self.suffix}"
        if levelname == "CRITICAL":
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
addLoggingLevel("SUCCESS", 25)
addLoggingLevel("VERBOSE", 15)
addLoggingLevel("STDOUT", 1)


def stop_listener(listener):
    with suppress(Exception):
        listener.stop()


def log_worker_setup(logging_queue):
    """
    This needs to be run whenever a new multiprocessing.Process() is spawned
    """
    log = logging.getLogger("bbot")
    # Don't do this more than once
    if len(log.handlers) == 0:
        log.setLevel(1)
        queue_handler = QueueHandler(logging_queue)
        log.addHandler(queue_handler)
    return log


def log_listener_setup(logging_queue, log_dir=None):

    if log_dir is None:
        log_dir = Path("~/.bbot/logs").expanduser()
    else:
        log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Log to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)

    # Log to stdout
    stdout_handler = logging.StreamHandler(sys.stdout)

    # Log debug messages to file
    debug_handler = logging.handlers.TimedRotatingFileHandler(
        f"{log_dir}/bbot.debug.log", when="d", interval=1, backupCount=14
    )

    # Log error messages to file
    error_handler = logging.handlers.TimedRotatingFileHandler(
        f"{log_dir}/bbot.error.log", when="d", interval=1, backupCount=14
    )

    # Filter by log level
    from bbot.core.configurator.args import cli_options

    stderr_loglevel = logging.INFO
    if cli_options is not None:
        if cli_options.verbose:
            stderr_loglevel = logging.VERBOSE
        if cli_options.debug:
            stderr_loglevel = logging.DEBUG
    stderr_handler.addFilter(lambda x: x.levelno >= stderr_loglevel)
    stdout_handler.addFilter(lambda x: x.levelno == 1)
    debug_handler.addFilter(lambda x: x.levelno >= logging.DEBUG)
    error_handler.addFilter(lambda x: x.levelno >= logging.WARN)

    # Set log format
    debug_format = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)s %(message)s")
    debug_handler.setFormatter(debug_format)
    error_handler.setFormatter(debug_format)
    stderr_handler.setFormatter(ColoredFormatter("%(levelname)s %(name)s: %(message)s"))
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))

    handlers = [stderr_handler, stdout_handler, debug_handler, error_handler]

    log_listener = QueueListener(logging_queue, *handlers)
    log_listener.start()
    atexit.register(stop_listener, log_listener)
    return {
        "stderr": stderr_handler,
        "stdout": stdout_handler,
        "file_debug": debug_handler,
        "file_error": error_handler,
    }


def init_logging(log_dir=None):
    """
    Initializes logging, returns logging queue and dictionary containing log handlers
    """

    logging_queue = Queue()
    handlers = log_listener_setup(logging_queue, log_dir=log_dir)
    log_worker_setup(logging_queue)

    return logging_queue, handlers
