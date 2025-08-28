import os
import sys
import atexit
import logging
from copy import copy
import multiprocessing
import logging.handlers
from pathlib import Path
from contextlib import suppress

from ..helpers.misc import mkdir, error_and_exit
from ..multiprocess import SHARED_INTERPRETER_STATE
from ...logger import colorize, loglevel_mapping, GzipRotatingFileHandler

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


class BBOTLogger:
    """
    The main BBOT logger.

    The job of this class is to manage the different log handlers in BBOT,
    allow adding new log handlers, and easily switching log levels on the fly.
    """

    def __init__(self, core):
        # custom logging levels
        if getattr(logging, "HUGEWARNING", None) is None:
            self.addLoggingLevel("TRACE", 49)
            self.addLoggingLevel("HUGEWARNING", 31)
            self.addLoggingLevel("HUGESUCCESS", 26)
            self.addLoggingLevel("SUCCESS", 25)
            self.addLoggingLevel("HUGEINFO", 21)
            self.addLoggingLevel("HUGEVERBOSE", 16)
            self.addLoggingLevel("VERBOSE", 15)
        self.verbosity_levels_toggle = [logging.INFO, logging.VERBOSE, logging.DEBUG]

        self._loggers = None
        self._log_handlers = None
        self._log_level = None
        self.core_logger = logging.getLogger("bbot")
        self.core = core

        self.listener = None

        # if we haven't set up logging yet, do it now
        if "_BBOT_LOGGING_SETUP" not in os.environ:
            os.environ["_BBOT_LOGGING_SETUP"] = "1"
            self.queue = multiprocessing.Queue()
            self.setup_queue_handler()
            # Start the QueueListener
            self.listener = logging.handlers.QueueListener(self.queue, *self.log_handlers.values())
            self.listener.start()
            atexit.register(self.cleanup_logging)

        self.log_level = logging.INFO

    def cleanup_logging(self):
        # Close the queue handler
        with suppress(Exception):
            self.queue_handler.close()

        # Clean all other loggers
        for logger in logging.Logger.manager.loggerDict.values():
            if hasattr(logger, "handlers"):  # Logger, not PlaceHolder
                for handler in list(logger.handlers):
                    with suppress(Exception):
                        logger.removeHandler(handler)
                    with suppress(Exception):
                        handler.close()

        # Stop queue listener
        with suppress(Exception):
            self.listener.stop()

    def setup_queue_handler(self, logging_queue=None, log_level=logging.DEBUG):
        if logging_queue is None:
            logging_queue = self.queue
        else:
            self.queue = logging_queue
        self.queue_handler = logging.handlers.QueueHandler(logging_queue)

        self.core_logger.addHandler(self.queue_handler)
        self.core_logger.setLevel(log_level)
        # disable asyncio logging for child processes
        if not SHARED_INTERPRETER_STATE.is_main_process:
            logging.getLogger("asyncio").setLevel(logging.ERROR)

    def addLoggingLevel(self, levelName, levelNum, methodName=None):
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

    @property
    def loggers(self):
        if self._loggers is None:
            self._loggers = [
                logging.getLogger("bbot"),
                logging.getLogger("asyncio"),
            ]
        return self._loggers

    def add_log_handler(self, handler, formatter=None):
        if self.listener is None:
            return
        if handler.formatter is None:
            handler.setFormatter(debug_format)
        if handler not in self.listener.handlers:
            self.listener.handlers = self.listener.handlers + (handler,)

    def remove_log_handler(self, handler):
        if self.listener is None:
            return
        if handler in self.listener.handlers:
            new_handlers = list(self.listener.handlers)
            new_handlers.remove(handler)
            self.listener.handlers = tuple(new_handlers)

    def include_logger(self, logger):
        if logger not in self.loggers:
            self.loggers.append(logger)
        if self.log_level is not None:
            logger.setLevel(self.log_level)
        for handler in self.log_handlers.values():
            self.add_log_handler(handler)

    def stderr_filter(self, record):
        if record.levelno == logging.TRACE and self.log_level > logging.DEBUG:
            return False
        if record.levelno < self.log_level:
            return False
        return True

    @property
    def log_handlers(self):
        if self._log_handlers is None:
            log_dir = Path(self.core.home) / "logs"
            if not mkdir(log_dir, raise_error=False):
                error_and_exit(f"Failure creating or error writing to BBOT logs directory ({log_dir})")

            # Main log file
            main_handler = GzipRotatingFileHandler(f"{log_dir}/bbot.log", maxBytes=1024 * 1024 * 100, backupCount=100)

            # Separate log file for debugging
            debug_handler = GzipRotatingFileHandler(
                f"{log_dir}/bbot.debug.log", maxBytes=1024 * 1024 * 100, backupCount=100
            )

            # Log to stderr
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.addFilter(self.stderr_filter)
            # log to files
            debug_handler.addFilter(lambda x: x.levelno == logging.TRACE or (x.levelno < logging.VERBOSE))
            main_handler.addFilter(lambda x: x.levelno != logging.TRACE and x.levelno >= logging.VERBOSE)

            # Set log format
            debug_handler.setFormatter(debug_format)
            main_handler.setFormatter(debug_format)
            stderr_handler.setFormatter(ColoredFormatter("%(levelname)s %(name)s: %(message)s"))

            self._log_handlers = {
                "stderr": stderr_handler,
                "file_debug": debug_handler,
                "file_main": main_handler,
            }
        return self._log_handlers

    @property
    def log_level(self):
        if self._log_level is None:
            return logging.INFO
        return self._log_level

    @log_level.setter
    def log_level(self, level):
        self.set_log_level(level)

    def set_log_level(self, level, logger=None):
        if isinstance(level, str):
            level = logging.getLevelName(level)
        if logger is not None:
            logger.hugeinfo(f"Setting log level to {logging.getLevelName(level)}")
        self._log_level = level
        for logger in self.loggers:
            logger.setLevel(level)

    def toggle_log_level(self, logger=None):
        if self.log_level in self.verbosity_levels_toggle:
            for i, level in enumerate(self.verbosity_levels_toggle):
                if self.log_level == level:
                    self.set_log_level(
                        self.verbosity_levels_toggle[(i + 1) % len(self.verbosity_levels_toggle)], logger=logger
                    )
                    break
        else:
            self.set_log_level(self.verbosity_levels_toggle[0], logger=logger)
