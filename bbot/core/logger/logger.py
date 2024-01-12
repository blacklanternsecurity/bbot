import os
import sys
import logging
from copy import copy
import logging.handlers
from pathlib import Path

from ..configurator import config
from ..helpers.misc import mkdir, error_and_exit
from ..helpers.logger import colorize, loglevel_mapping


_log_level_override = None

bbot_loggers = None
bbot_log_handlers = None

debug_format = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(filename)s:%(lineno)s %(message)s")


class ColoredFormatter(logging.Formatter):
    """
    Pretty colors for terminal
    """

    formatter = logging.Formatter("%(levelname)s %(message)s")
    module_formatter = logging.Formatter("%(levelname)s %(name)s: %(message)s")

    def format(self, record):
        colored_record = copy(record)
        levelname = colored_record.levelname
        levelshort = loglevel_mapping.get(levelname, "INFO")
        colored_record.levelname = colorize(f"[{levelshort}]", level=levelname)
        if levelname == "CRITICAL" or levelname.startswith("HUGE"):
            colored_record.msg = colorize(colored_record.msg, level=levelname)
        # remove name
        if colored_record.name.startswith("bbot.modules."):
            colored_record.name = colored_record.name.split("bbot.modules.")[-1]
            return self.module_formatter.format(colored_record)
        return self.formatter.format(colored_record)


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
        raise AttributeError(f"{levelName} already defined in logging module")
    if hasattr(logging, methodName):
        raise AttributeError(f"{methodName} already defined in logging module")
    if hasattr(logging.getLoggerClass(), methodName):
        raise AttributeError(f"{methodName} already defined in logger class")

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


def get_bbot_loggers():
    global bbot_loggers
    if bbot_loggers is None:
        bbot_loggers = [
            logging.getLogger("bbot"),
            logging.getLogger("asyncio"),
        ]
    return bbot_loggers


def add_log_handler(handler, formatter=None):
    if handler.formatter is None:
        handler.setFormatter(debug_format)
    for logger in get_bbot_loggers():
        if handler not in logger.handlers:
            logger.addHandler(handler)


def remove_log_handler(handler):
    for logger in get_bbot_loggers():
        if handler in logger.handlers:
            logger.removeHandler(handler)


def init_logging():
    # Don't do this more than once
    if len(logging.getLogger("bbot").handlers) == 0:
        for logger in get_bbot_loggers():
            include_logger(logger)


def include_logger(logger):
    bbot_loggers = get_bbot_loggers()
    if logger not in bbot_loggers:
        bbot_loggers.append(logger)
    logger.setLevel(get_log_level())
    for handler in get_log_handlers().values():
        logger.addHandler(handler)


def get_log_handlers():
    global bbot_log_handlers

    if bbot_log_handlers is None:
        log_dir = Path(config["home"]) / "logs"
        if not mkdir(log_dir, raise_error=False):
            error_and_exit(f"Failure creating or error writing to BBOT logs directory ({log_dir})")

        # Main log file
        main_handler = logging.handlers.TimedRotatingFileHandler(
            f"{log_dir}/bbot.log", when="d", interval=1, backupCount=14
        )

        # Separate log file for debugging
        debug_handler = logging.handlers.TimedRotatingFileHandler(
            f"{log_dir}/bbot.debug.log", when="d", interval=1, backupCount=14
        )

        def stderr_filter(record):
            log_level = get_log_level()
            if record.levelno == logging.STDOUT or (record.levelno == logging.TRACE and log_level > logging.DEBUG):
                return False
            if record.levelno < log_level:
                return False
            return True

        # Log to stderr
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.addFilter(stderr_filter)
        # Log to stdout
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.addFilter(lambda x: x.levelno == logging.STDOUT)
        # log to files
        debug_handler.addFilter(
            lambda x: x.levelno == logging.TRACE or (x.levelno < logging.VERBOSE and x.levelno != logging.STDOUT)
        )
        main_handler.addFilter(
            lambda x: x.levelno not in (logging.STDOUT, logging.TRACE) and x.levelno >= logging.VERBOSE
        )

        # Set log format
        debug_handler.setFormatter(debug_format)
        main_handler.setFormatter(debug_format)
        stderr_handler.setFormatter(ColoredFormatter("%(levelname)s %(name)s: %(message)s"))
        stdout_handler.setFormatter(logging.Formatter("%(message)s"))

        bbot_log_handlers = {
            "stderr": stderr_handler,
            "stdout": stdout_handler,
            "file_debug": debug_handler,
            "file_main": main_handler,
        }
    return bbot_log_handlers


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
    for logger in bbot_loggers:
        logger.setLevel(level)


def toggle_log_level(logger=None):
    log_level = get_log_level()
    if log_level in verbosity_levels_toggle:
        for i, level in enumerate(verbosity_levels_toggle):
            if log_level == level:
                set_log_level(verbosity_levels_toggle[(i + 1) % len(verbosity_levels_toggle)], logger=logger)
    else:
        set_log_level(verbosity_levels_toggle[0], logger=logger)
