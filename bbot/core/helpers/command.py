import os
import asyncio
import logging
import traceback
from signal import SIGINT
from subprocess import CompletedProcess, CalledProcessError, SubprocessError

from .misc import smart_decode, smart_encode, which

log = logging.getLogger("bbot.core.helpers.command")


async def run(self, *command, check=False, text=True, idle_timeout=None, **kwargs):
    """Runs a command asynchronously and gets its output as a string.

    This method is a simple helper for executing a command and capturing its output.
    If an error occurs during execution, it can optionally raise an error or just log the stderr.

    Args:
        *command (str): The command to run as separate arguments.
        check (bool, optional): If set to True, raises an error if the subprocess exits with a non-zero status.
                                Defaults to False.
        text (bool, optional): If set to True, decodes the subprocess output to string. Defaults to True.
        idle_timeout (int, optional): Sets a limit on the number of seconds the process can run before throwing a TimeoutError
        **kwargs (dict): Additional keyword arguments for the subprocess.

    Returns:
        CompletedProcess: A completed process object with attributes for the command, return code, stdout, and stderr.

    Raises:
        CalledProcessError: If the subprocess exits with a non-zero status and `check=True`.

    Examples:
        >>> process = await run(["ls", "/tmp"])
        >>> process.stdout
        "file1.txt\nfile2.txt"
    """
    # proc_tracker optionally keeps track of which processes are running under which modules
    # this allows for graceful SIGINTing of a module's processes in the case when it's killed
    proc_tracker = kwargs.pop("_proc_tracker", set())
    log_stderr = kwargs.pop("_log_stderr", True)
    proc, _input, command = await self._spawn_proc(*command, **kwargs)
    if proc is not None:
        proc_tracker.add(proc)
        try:
            if _input is not None:
                if isinstance(_input, (list, tuple)):
                    _input = b"\n".join(smart_encode(i) for i in _input) + b"\n"
                else:
                    _input = smart_encode(_input)

            try:
                if idle_timeout is not None:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(_input), timeout=idle_timeout)
                else:
                    stdout, stderr = await proc.communicate(_input)
            except asyncio.exceptions.TimeoutError:
                proc.send_signal(SIGINT)
                raise

            # surface stderr
            if text:
                if stderr is not None:
                    stderr = smart_decode(stderr)
                if stdout is not None:
                    stdout = smart_decode(stdout)
            if proc.returncode:
                if check:
                    raise CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)
                if stderr and log_stderr:
                    command_str = " ".join(command)
                    log.warning(f"Stderr for run({command_str}):\n\t{stderr}")

            return CompletedProcess(command, proc.returncode, stdout, stderr)
        finally:
            proc_tracker.remove(proc)


async def run_live(self, *command, check=False, text=True, idle_timeout=None, **kwargs):
    """Runs a command asynchronously and iterates through its output line by line in realtime.

    This method is useful for executing a command and capturing its output on-the-fly, as it is generated.
    If an error occurs during execution, it can optionally raise an error or just log the stderr.

    Args:
        *command (str): The command to run as separate arguments.
        check (bool, optional): If set to True, raises an error if the subprocess exits with a non-zero status.
                                Defaults to False.
        text (bool, optional): If set to True, decodes the subprocess output to string. Defaults to True.
        idle_timeout (int, optional): Sets a limit on the number of seconds the process can remain idle (no lines sent to stdout) before throwing a TimeoutError
        **kwargs (dict): Additional keyword arguments for the subprocess.

    Yields:
        str or bytes: The output lines of the command, either as a decoded string (if `text=True`)
                      or as bytes (if `text=False`).

    Raises:
        CalledProcessError: If the subprocess exits with a non-zero status and `check=True`.

    Examples:
        >>> async for line in run_live(["tail", "-f", "/var/log/auth.log"]):
        ...     log.info(line)
    """
    # proc_tracker optionally keeps track of which processes are running under which modules
    # this allows for graceful SIGINTing of a module's processes in the case when it's killed
    proc_tracker = kwargs.pop("_proc_tracker", set())
    log_stderr = kwargs.pop("_log_stderr", True)
    proc, _input, command = await self._spawn_proc(*command, **kwargs)
    if proc is not None:
        proc_tracker.add(proc)
        try:
            input_task = None
            if _input is not None:
                input_task = asyncio.create_task(_write_stdin(proc, _input))

            while 1:
                try:
                    if idle_timeout is not None:
                        line = await asyncio.wait_for(proc.stdout.readline(), timeout=idle_timeout)
                    else:
                        line = await proc.stdout.readline()
                except asyncio.exceptions.TimeoutError:
                    proc.send_signal(SIGINT)
                    raise
                except ValueError as e:
                    command_str = " ".join(command)
                    log.warning(f"Error executing command {command_str}: {e}")
                    log.trace(traceback.format_exc())
                    continue
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
                except ConnectionError:
                    log.trace(f"ConnectionError in command: {command}, kwargs={kwargs}")
                    log.trace(traceback.format_exc())
            await proc.wait()

            if proc.returncode:
                stdout, stderr = await proc.communicate()
                if text:
                    if stderr is not None:
                        stderr = smart_decode(stderr)
                    if stdout is not None:
                        stdout = smart_decode(stdout)
                if check:
                    raise CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)
                # surface stderr
                if stderr and log_stderr:
                    command_str = " ".join(command)
                    log.warning(f"Stderr for run_live({command_str}):\n\t{stderr}")
        finally:
            proc_tracker.remove(proc)


async def _spawn_proc(self, *command, **kwargs):
    """Spawns an asynchronous subprocess.

    Prepares the command and associated keyword arguments. If the `input` argument is provided,
    it checks to ensure that the `stdin` argument is not also provided. Once prepared, it creates
    and returns the subprocess. If the command executable is not found, it logs a warning and traceback.

    Args:
        *command (str): The command to run as separate arguments.
        **kwargs (dict): Additional keyword arguments for the subprocess.

    Raises:
        ValueError: If both stdin and input arguments are provided.

    Returns:
        tuple: A tuple containing the created process (or None if creation failed), the input (or None if not provided),
               and the prepared command (or None if subprocess creation failed).

    Examples:
        >>> _spawn_proc("ls", "-l", input="data")
        (<Process ...>, "data", ["ls", "-l"])
    """
    try:
        command, kwargs = self._prepare_command_kwargs(command, kwargs)
    except SubprocessError as e:
        command_str = " ".join([str(s) for s in command])
        log.warning(f"Error running command: '{command_str}': {e}")
        log.trace(traceback.format_exc())
        return None, None, None
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


async def _write_proc_line(proc, chunk):
    try:
        proc.stdin.write(smart_encode(chunk) + b"\n")
        await proc.stdin.drain()
        return True
    except Exception as e:
        proc_args = [str(s) for s in getattr(proc, "args", [])]
        command = " ".join(proc_args).strip()
        if command:
            log.warning(f"Error writing line to stdin for command: {command}: {e}")
            log.trace(traceback.format_exc())
        return False


async def _write_stdin(proc, _input):
    """
    Asynchronously writes input to an active subprocess's stdin.

    This function takes an `_input` parameter, which can be of type str, bytes,
    list, tuple, or an asynchronous generator. The input is then written line by
    line to the stdin of the given `proc`.

    Args:
        proc (subprocess.Popen): An active subprocess object.
        _input (str, bytes, list, tuple, async generator): The data to write to stdin.
    """
    if _input is not None:
        if isinstance(_input, (str, bytes)):
            _input = [_input]
        if isinstance(_input, (list, tuple)):
            for chunk in _input:
                write_result = await _write_proc_line(proc, chunk)
                if not write_result:
                    break
        else:
            async for chunk in _input:
                write_result = await _write_proc_line(proc, chunk)
                if not write_result:
                    break
        proc.stdin.close()


def _prepare_command_kwargs(self, command, kwargs):
    """
    Prepare arguments for passing into `asyncio.create_subprocess_exec()`.

    This method modifies the `kwargs` dictionary in place to prepare it for
    use in the `asyncio.create_subprocess_exec()` method. It sets the default
    values for keys like 'limit', 'stdout', and 'stderr' if they are not
    already present. It also handles the case when 'sudo' needs to be run.

    Args:
        command (list): The command to be run in the subprocess.
        kwargs (dict): The keyword arguments to be passed to `asyncio.create_subprocess_exec()`.

    Returns:
        tuple: A tuple containing the modified `command` and `kwargs`.

    Examples:
        >>> _prepare_command_kwargs(['ls', '-l'], {})
        (['ls', '-l'], {'limit': 104857600, 'stdout': -1, 'stderr': -1})

        >>> _prepare_command_kwargs(['ls', '-l'], {'sudo': True})
        (['sudo', '-E', '-A', 'LD_LIBRARY_PATH=...', 'PATH=...', 'ls', '-l'], {'limit': 104857600, 'stdout': -1, 'stderr': -1, 'env': environ(...)})
    """
    # limit = 100MB (this is needed for cases like httpx that are sending large JSON blobs over stdout)
    if "limit" not in kwargs:
        kwargs["limit"] = 1024 * 1024 * 100
    if "stdout" not in kwargs:
        kwargs["stdout"] = asyncio.subprocess.PIPE
    if "stderr" not in kwargs:
        kwargs["stderr"] = asyncio.subprocess.PIPE
    sudo = kwargs.pop("sudo", False)

    if len(command) == 1 and isinstance(command[0], (list, tuple)):
        command = command[0]

    command = [str(s) for s in command]

    if not command:
        raise SubprocessError("Must specify a command")

    # use full path of binary, if not already specified
    binary = command[0]
    if "/" not in binary:
        binary_full_path = which(binary)
        if binary_full_path is None:
            raise SubprocessError(f'Command "{binary}" was not found')
        command[0] = binary_full_path

    env = kwargs.get("env", os.environ)
    if sudo and os.geteuid() != 0:
        self.depsinstaller.ensure_root()
        env["SUDO_ASKPASS"] = str((self.tools_dir / self.depsinstaller.askpass_filename).resolve())
        env["BBOT_SUDO_PASS"] = self.depsinstaller.encrypted_sudo_pw
        kwargs["env"] = env

        PATH = os.environ.get("PATH", "")
        LD_LIBRARY_PATH = os.environ.get("LD_LIBRARY_PATH", "")
        command = ["sudo", "-E", "-A", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}", f"PATH={PATH}"] + command
    return command, kwargs
