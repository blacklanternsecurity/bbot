import io
import logging
import subprocess
from contextlib import suppress

from .misc import smart_encode

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

    log.debug(f"run_live{input_msg}: {' '.join(command)}")

    with subprocess.Popen(command, *args, **kwargs) as process:
        if _input:
            process.stdin.write(smart_encode(_input))
            with suppress(Exception):
                process.stdin.close()
        for line in io.TextIOWrapper(process.stdout, encoding="utf-8", errors="ignore"):
            yield line


def run(self, command, *args, **kwargs):

    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    if not "text" in kwargs:
        kwargs["text"] = True

    log.debug(f"run: {' '.join(command)}")
    result = subprocess.run(command, *args, **kwargs)
    return result
