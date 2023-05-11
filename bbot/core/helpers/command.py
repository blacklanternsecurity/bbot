import os
import asyncio
import logging
import traceback
from subprocess import CompletedProcess, CalledProcessError

from .misc import smart_decode, smart_encode

log = logging.getLogger("bbot.core.helpers.command")


async def run(self, *command, check=False, text=True, **kwargs):
    """
    Simple helper for running a command, and getting its output as a string
        process = await run(["ls", "/tmp"])
        process.stdout --> "file1.txt\nfile2.txt"
    """
    proc, _input, command = await self._spawn_proc(*command, **kwargs)
    if proc is not None:
        if _input is not None:
            if isinstance(_input, (list, tuple)):
                _input = b"\n".join(smart_encode(i) for i in _input) + b"\n"
            else:
                _input = smart_encode(_input)
        stdout, stderr = await proc.communicate(_input)

        # surface stderr
        if text:
            stderr = smart_decode(stderr)
            stdout = smart_decode(stdout)
        if proc.returncode:
            if check:
                raise CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)
            if stderr:
                command_str = " ".join(command)
                log.warning(f"Stderr for run({command_str}):\n\t{stderr}")

        return CompletedProcess(command, proc.returncode, stdout, stderr)


async def run_live(self, *command, check=False, text=True, **kwargs):
    """
    Simple helper for running a command and iterating through its output line by line in realtime
        async for line in run_live(["ls", "/tmp"]):
            log.info(line)
    """
    proc, _input, command = await self._spawn_proc(*command, **kwargs)
    if proc is not None:
        input_task = None
        if _input is not None:
            input_task = asyncio.create_task(_write_stdin(proc, _input))

        while 1:
            line = await proc.stdout.readline()
            if not line:
                break
            if text:
                line = smart_decode(line).rstrip("\r\n")
            else:
                line = line.rstrip(b"\r\n")
            yield line

        if input_task is not None:
            try:
                await input_task
            except BrokenPipeError:
                log.trace(traceback.format_exc())
        await proc.wait()

        if proc.returncode:
            stdout, stderr = await proc.communicate()
            if text:
                stderr = smart_decode(stderr)
                stdout = smart_decode(stdout)
            if check:
                raise CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)
            # surface stderr
            if stderr:
                command_str = " ".join(command)
                log.warning(f"Stderr for run_live({command_str}):\n\t{stderr}")


async def _spawn_proc(self, *command, **kwargs):
    command, kwargs = self._prepare_command_kwargs(command, kwargs)
    _input = kwargs.pop("input", None)
    if _input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        kwargs["stdin"] = asyncio.subprocess.PIPE

    log.hugeverbose(f"run: {' '.join(command)}")
    try:
        proc = await asyncio.create_subprocess_exec(*command, **kwargs)
        return proc, _input, command
    except FileNotFoundError as e:
        log.warning(f"{e} - missing executable?")
        log.trace(traceback.format_exc())
    return None, None, None


async def _write_stdin(proc, _input):
    if _input is not None:
        if isinstance(_input, (str, bytes)):
            _input = [_input]
        if isinstance(_input, (list, tuple)):
            for chunk in _input:
                proc.stdin.write(smart_encode(chunk) + b"\n")
        else:
            async for chunk in _input:
                proc.stdin.write(smart_encode(chunk) + b"\n")
        await proc.stdin.drain()
        proc.stdin.close()


def _prepare_command_kwargs(self, command, kwargs):
    # limit = 10MB (this is needed for cases like httpx that are sending large JSON blobs over stdout)
    kwargs["limit"] = 1024 * 1024 * 10
    if not "stdout" in kwargs:
        kwargs["stdout"] = asyncio.subprocess.PIPE
    if not "stderr" in kwargs:
        kwargs["stderr"] = asyncio.subprocess.PIPE
    sudo = kwargs.pop("sudo", False)

    if len(command) == 1 and isinstance(command[0], (list, tuple)):
        command = command[0]
    command = [str(s) for s in command]

    env = kwargs.get("env", os.environ)
    if sudo and os.geteuid() != 0:
        self.depsinstaller.ensure_root()
        env["SUDO_ASKPASS"] = str((self.tools_dir / self.depsinstaller.askpass_filename).resolve())
        env["BBOT_SUDO_PASS"] = self.depsinstaller._sudo_password
        kwargs["env"] = env

        PATH = os.environ.get("PATH", "")
        LD_LIBRARY_PATH = os.environ.get("LD_LIBRARY_PATH", "")
        command = ["sudo", "-E", "-A", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}", f"PATH={PATH}"] + command
    return command, kwargs
