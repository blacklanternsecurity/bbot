import io
import os
import logging
import threading
import subprocess
from contextlib import suppress

log = logging.getLogger("bbot.core.helpers.command")


def run_live(self, command, *args, **kwargs):

    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    _input = kwargs.pop("input", "")
    input_msg = ""
    if _input:
        kwargs["stdin"] = subprocess.PIPE
        input_msg = " (with stdin)"

    command = [str(s) for s in command]
    log.verbose(f"run_live{input_msg}: {' '.join(command)}")
    with subprocess.Popen(command, *args, **kwargs) as process:
        if _input:
            if type(_input) in (str, bytes):
                _input = (_input,)
            self.feed_pipe(process.stdin, _input, text=False)
        for line in io.TextIOWrapper(process.stdout, encoding="utf-8", errors="ignore"):
            yield line


def run(self, command, *args, **kwargs):

    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    if not "text" in kwargs:
        kwargs["text"] = True

    command = [str(s) for s in command]
    log.verbose(f"run: {' '.join(command)}")
    result = subprocess.run(command, *args, **kwargs)
    return result


def tempfile(self, content, pipe=True):
    """
    if "pipe" is True, a named pipe is used instead
    This allows python data to be piped directly into the process
    by effectively "spoofing" a file and without taking up disk space
    """
    try:
        filename = self.temp_filename()
        if type(content) not in (set, list, tuple):
            content = (content,)
        if pipe:
            os.mkfifo(filename)
            self.feed_pipe(filename, content, text=True)
        else:
            with open(filename, "w", errors="ignore") as f:
                for c in content:
                    f.write(f"{self.smart_decode(c)}\n")
    except Exception as e:
        import traceback

        log.error(f"Error creating temp file: {e}")
        log.debug(traceback.format_exc())

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
            log.debug("Broken pipe in _feed_pipe()")
    except KeyboardInterrupt:
        self.scan.stop()
    except Exception as e:
        import traceback

        log.error(f"Error in _feed_pipe(): {e}")
        log.debug(traceback.format_exc())


def feed_pipe(self, pipe, content, text=True):
    t = threading.Thread(target=self._feed_pipe, args=(pipe, content), kwargs={"text": text}, daemon=True)
    t.start()
