import os
import logging
import traceback
from contextlib import suppress

from .misc import rm_at_exit


log = logging.getLogger("bbot.core.helpers.files")


def tempfile(self, content, pipe=True):
    """
    Creates a temporary file or named pipe and populates it with content.

    Args:
        content (list, set, tuple, str): The content to populate the temporary file with.
        pipe (bool, optional): If True, a named pipe is used instead of a true file.
            This allows Python data to be piped directly into the process without taking up disk space.
            Defaults to True.

    Returns:
        str: The filepath of the created temporary file or named pipe.

    Examples:
        >>> tempfile(["This", "is", "temp", "content"])
        '/home/user/.bbot/temp/pgxml13bov87oqrvjz7a'

        >>> tempfile(["Another", "temp", "file"], pipe=False)
        '/home/user/.bbot/temp/someotherfile'
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
    """
    Feeds content into a named pipe or file-like object.

    Args:
        pipe (str or file-like object): The named pipe or file-like object to feed the content into.
        content (iterable): The content to be written into the pipe or file.
        text (bool, optional): If True, the content is decoded using smart_decode function.
            If False, smart_encode function is used. Defaults to True.

    Notes:
        The method tries to determine if 'pipe' is a file-like object that has a 'write' method.
        If so, it writes directly to that object. Otherwise, it opens 'pipe' as a file for writing.
    """
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
        except ValueError:
            log.debug(f"Error _feed_pipe(): {traceback.format_exc()}")
    except KeyboardInterrupt:
        self.scan.stop()
    except Exception as e:
        log.error(f"Error in _feed_pipe(): {e}")
        log.trace(traceback.format_exc())


def feed_pipe(self, pipe, content, text=True):
    """
    Starts a new thread to feed content into a named pipe or file-like object using _feed_pipe().

    Args:
        pipe (str or file-like object): The named pipe or file-like object to feed the content into.
        content (iterable): The content to be written into the pipe or file.
        text (bool, optional): If True, the content is decoded using smart_decode function.
            If False, smart_encode function is used. Defaults to True.
    """
    t = self.preset.core.create_thread(
        target=self._feed_pipe,
        args=(pipe, content),
        kwargs={"text": text},
        daemon=True,
        custom_name="bbot feed_pipe()",
    )
    t.start()


def tempfile_tail(self, callback):
    """
    Create a named pipe and execute a callback function on each line that is written to the pipe.

    Useful for ingesting output from a program (e.g. nuclei) directly from a file in real-time as
    each line is written. The idea is you create the file with this function and then tell the CLI
    program to output to it as a normal output file. We are then able to scoop up the output line
    by line as it's written to our "file" (which is actually a named pipe, shhh! ;)

    Args:
        callback (Callable): A function that will be invoked with each line written to the pipe as its argument.

    Returns:
        str: The filename of the created named pipe.
    """
    filename = self.temp_filename()
    rm_at_exit(filename)
    try:
        os.mkfifo(filename)
        t = self.preset.core.create_thread(
            target=tail, args=(filename, callback), daemon=True, custom_name="bbot tempfile_tail()"
        )
        t.start()
    except Exception as e:
        log.error(f"Error setting up tail for file {filename}: {e}")
        log.trace(traceback.format_exc())
        return
    return filename


def tail(filename, callback):
    """
    Continuously read lines from a file and execute a callback function on each line.

    Args:
        filename (str): The path of the file to tail.
        callback (Callable): A function to call on each line read from the file.

    Examples:
        >>> def print_callback(line):
        ...     print(f"Received: {line}")
        >>> tail("/path/to/file", print_callback)
    """
    try:
        with open(filename, errors="ignore") as f:
            for line in f:
                line = line.rstrip("\r\n")
                callback(line)
    except Exception as e:
        log.error(f"Error tailing file {filename}: {e}")
        log.trace(traceback.format_exc())
