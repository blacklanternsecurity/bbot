import os
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
from ..helpers.logger import colorize, loglevel_mapping


_log_level_override = None


class ColoredFormatter(logging.Formatter):
    """
    Pretty colors for terminal
    """

    def format(self, record):
        colored_record = copy(record)
        levelname = colored_record.levelname
        levelshort = loglevel_mapping.get(levelname, "INFO")
        colored_record.levelname = colorize(f"[{levelshort}]", level=levelname)
        if levelname == "CRITICAL" or levelname.startswith("HUGE"):
            colored_record.msg = colorize(colored_record.msg, level=levelname)
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
addLoggingLevel("TRACE", 49)
addLoggingLevel("HUGEWARNING", 31)
addLoggingLevel("HUGESUCCESS", 26)
addLoggingLevel("SUCCESS", 25)
addLoggingLevel("HUGEINFO", 21)
addLoggingLevel("HUGEVERBOSE", 16)
addLoggingLevel("VERBOSE", 15)


verbosity_levels_toggle = [logging.INFO, logging.VERBOSE, logging.DEBUG]


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

    def stderr_filter(record):
        config_silent = config.get("silent", False)
        log_level = get_log_level()
        excluded_levels = [logging.STDOUT]
        if log_level > logging.DEBUG:
            excluded_levels.append(logging.TRACE)
        if record.levelno in excluded_levels:
            return False
        if record.levelno >= logging.ERROR:
            return True
        if record.levelno < log_level:
            return False
        if config_silent and not record.levelname.startswith("HUGE"):
            return False
        return True

    stderr_handler.addFilter(stderr_filter)
    stdout_handler.addFilter(lambda x: x.levelno == logging.STDOUT)
    debug_handler.addFilter(lambda x: x.levelno != logging.STDOUT and x.levelno >= logging.DEBUG)
    main_handler.addFilter(lambda x: x.levelno not in (logging.STDOUT, logging.TRACE) and x.levelno >= logging.VERBOSE)

    # Set log format
    debug_format = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)s %(message)s")
    debug_handler.setFormatter(debug_format)
    main_handler.setFormatter(debug_format)
    stderr_handler.setFormatter(ColoredFormatter("%(levelname)s %(name)s: %(message)s"))
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))

    handlers = [stdout_handler, stderr_handler, main_handler, debug_handler]

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
    if _log_level_override is not None:
        return _log_level_override

    from bbot.core.configurator.args import cli_options

    if config.get("debug", False) or os.environ.get("BBOT_DEBUG", "").lower() in ("true", "yes"):
        return logging.DEBUG

    loglevel = logging.INFO
    if cli_options is not None:
        if cli_options.verbose:
            loglevel = logging.VERBOSE
        if cli_options.debug:
            loglevel = logging.DEBUG
    return loglevel


def set_log_level(level, logger=None):
    global _log_level_override
    if logger is not None:
        logger.hugeinfo(f"Setting log level to {logging.getLevelName(level)}")
    config["silent"] = False
    _log_level_override = level
    log = logging.getLogger("bbot")
    log.setLevel(level)


def toggle_log_level(logger=None):
    log_level = get_log_level()
    if log_level in verbosity_levels_toggle:
        for i, level in enumerate(verbosity_levels_toggle):
            if log_level == level:
                set_log_level(verbosity_levels_toggle[(i + 1) % len(verbosity_levels_toggle)], logger=logger)
    else:
        set_log_level(verbosity_levels_toggle[0], logger=logger)
