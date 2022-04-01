import io
import logging
import subprocess

log = logging.getLogger("bbot.core.helpers.command")


def run_live(self, command, *args, **kwargs):

    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE

    log.debug(f"Running command: {' '.join(command)}")

    with subprocess.Popen(command, *args, **kwargs) as process:
        for line in io.TextIOWrapper(process.stdout, encoding="utf-8", errors="ignore"):
            yield line


def run(self, command, *args, **kwargs):

    if not "stdout" in kwargs:
        kwargs["stdout"] = subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = subprocess.PIPE
    if not "text" in kwargs:
        kwargs["text"] = True

    log.debug(f"Running command: {' '.join(command)}")
    result = subprocess.run(command, *args, **kwargs)
    return result
