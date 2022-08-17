import io
import os
import logging
import threading
import subprocess
from contextlib import suppress

from .misc import smart_decode

log = logging.getLogger("bbot.core.helpers.command")


def run_live(self, command, *args, **kwargs):
    """
    Get live output, line by line, as a process executes
    You can also pass input=<iterator> and pipe data into the process' stdin
        - This lets you chain processes like so:

            ls_process = run_live(["ls", "/etc"])
            grep_process = run_live(["grep", "conf"], input=ls_process)
            for line in grep_process:
                log.success(line)

        - The above is roughly equivalent to:
            ls /etc | grep conf

    NOTE: STDERR is hidden by default.
        If you want to see it, pass stderr=None
    """

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
    log.hugeverbose(f"run_live{input_msg}: {' '.join(command)}")
    with catch(subprocess.Popen, command, *args, **kwargs) as process:
        if _input:
            if type(_input) in (str, bytes):
                _input = (_input,)
            self.feed_pipe(process.stdin, _input, text=False)
        for line in io.TextIOWrapper(process.stdout, encoding="utf-8", errors="ignore"):
            yield line

        # surface stderr
        process.wait()
        if process.stderr and process.returncode != 0:
            stderr = smart_decode(process.stderr.read())
            if stderr:
                command_str = " ".join(command)
                log.warning(f"Stderr for {command_str}:\n\t{stderr}")


def run(self, command, *args, **kwargs):
    """
    Simple helper for running a command, and getting its output as a string
        process = run(["ls", "/tmp"])
        process.stdout --> "file1.txt\nfile2.txt"

    NOTE: STDERR is captured (not displayed) by default.
        If you want to see it, self.debug(process.stderr) or pass stderr=None
    """
    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    if not "text" in kwargs:
        kwargs["text"] = True

    command = [str(s) for s in command]
    log.hugeverbose(f"run: {' '.join(command)}")
    result = catch(subprocess.run, command, *args, **kwargs)

    # surface stderr
    if result.stderr and result.returncode != 0:
        stderr = smart_decode(result.stderr)
        if stderr:
            command_str = " ".join(command)
            log.warning(f"Stderr for {command_str}:\n\t{stderr}")

    return result


def catch(callback, *args, **kwargs):
    try:
        return callback(*args, **kwargs)
    except FileNotFoundError as e:
        import traceback

        log.warning(f"{e} - missing executable?")
        log.debug(traceback.format_exc())
    except BrokenPipeError as e:
        import traceback

        log.warning(f"Error in subprocess: {e}")
        log.debug(traceback.format_exc())


def tempfile(self, content, pipe=True):
    """
    tempfile("temp\nfile\ncontent") --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")

    if "pipe" is True (the default), a named pipe is used instead of
    a true file, which allows python data to be piped directly into the
    process without taking up disk space
    """
    filename = self.temp_filename()
    try:
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
            log.debug(f"Broken pipe in _feed_pipe()")
        except ValueError:
            import traceback

            log.debug(f"Error _feed_pipe(): {traceback.format_exc()}")
    except KeyboardInterrupt:
        self.scan.stop()
    except Exception as e:
        import traceback

        log.error(f"Error in _feed_pipe(): {e}")
        log.debug(traceback.format_exc())


def feed_pipe(self, pipe, content, text=True):
    t = threading.Thread(target=self._feed_pipe, args=(pipe, content), kwargs={"text": text}, daemon=True)
    t.start()
