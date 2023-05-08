import os
import logging
import threading
import traceback
from contextlib import suppress

from .misc import rm_at_exit


log = logging.getLogger("bbot.core.helpers.files")


def tempfile(self, content, pipe=True):
    """
    tempfile(["temp", "file", "content"]) --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")

    if "pipe" is True (the default), a named pipe is used instead of
    a true file, which allows python data to be piped directly into the
    process without taking up disk space
    """
    filename = self.temp_filename()
    rm_at_exit(filename)
    try:
        if type(content) not in (set, list, tuple):
            content = (content,)
        if pipe:
            os.mkfifo(filename)
            self.feed_pipe(filename, content, text=True)
        else:
            with open(filename, "w", errors="ignore") as f:
                for c in content:
                    line = f"{self.smart_decode(c)}\n"
                    f.write(line)
    except Exception as e:
        log.error(f"Error creating temp file: {e}")
        log.trace(traceback.format_exc())

    return filename


def _feed_pipe(self, pipe, content, text=True):
    try:
        if text:
            decode_fn = self.smart_decode
            newline = "\n"
        else:
            decode_fn = self.smart_encode
            newline = b"\n"
        try:
            if hasattr(pipe, "write"):
                try:
                    for c in content:
                        pipe.write(decode_fn(c) + newline)
                finally:
                    with suppress(Exception):
                        pipe.close()
            else:
                with open(pipe, "w") as p:
                    for c in content:
                        p.write(decode_fn(c) + newline)
        except BrokenPipeError:
            log.debug(f"Broken pipe in _feed_pipe()")
        except ValueError:
            log.debug(f"Error _feed_pipe(): {traceback.format_exc()}")
    except KeyboardInterrupt:
        self.scan.stop()
    except Exception as e:
        log.error(f"Error in _feed_pipe(): {e}")
        log.trace(traceback.format_exc())


def feed_pipe(self, pipe, content, text=True):
    t = threading.Thread(target=self._feed_pipe, args=(pipe, content), kwargs={"text": text}, daemon=True)
    t.start()


def tempfile_tail(self, callback):
    """
    Create a named pipe and execute a callback on each line
    """
    filename = self.temp_filename()
    rm_at_exit(filename)
    try:
        os.mkfifo(filename)
        t = threading.Thread(target=tail, args=(filename, callback), daemon=True)
        t.start()
    except Exception as e:
        log.error(f"Error setting up tail for file {filename}: {e}")
        log.trace(traceback.format_exc())
        return
    return filename


def tail(filename, callback):
    try:
        with open(filename, errors="ignore") as f:
            for line in f:
                line = line.rstrip("\r\n")
                callback(line)
    except Exception as e:
        log.error(f"Error tailing file {filename}: {e}")
        log.trace(traceback.format_exc())
