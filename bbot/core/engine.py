import os
import sys
import zmq
import pickle
import asyncio
import inspect
import logging
import tempfile
import traceback
import contextlib
import contextvars
import zmq.asyncio
from pathlib import Path
from concurrent.futures import CancelledError
from contextlib import asynccontextmanager, suppress

from bbot.core import CORE
from bbot.errors import BBOTEngineError
from bbot.core.helpers.async_helpers import get_event_loop
from bbot.core.helpers.misc import rand_string, in_exception_chain


error_sentinel = object()


class EngineBase:
    """
    Base Engine class for Server and Client.

    An Engine is a simple and lightweight RPC implementation that allows offloading async tasks
    to a separate process. It leverages ZeroMQ in a ROUTER-DEALER configuration.

    BBOT makes use of this by spawning a dedicated engine for DNS and HTTP tasks.
    This offloads I/O and helps free up the main event loop for other tasks.

    To use Engine, you must subclass both EngineClient and EngineServer.

    See the respective EngineClient and EngineServer classes for usage examples.
    """

    ERROR_CLASS = BBOTEngineError

    def __init__(self, debug=False):
        self._shutdown_status = False
        self.log = logging.getLogger(f"bbot.core.{self.__class__.__name__.lower()}")
        self._engine_debug = debug

    def pickle(self, obj):
        try:
            return pickle.dumps(obj)
        except Exception as e:
            self.log.error(f"Error serializing object: {obj}: {e}")
            self.log.trace(traceback.format_exc())
        return error_sentinel

    def unpickle(self, binary):
        try:
            return pickle.loads(binary)
        except Exception as e:
            self.log.error(f"Error deserializing binary: {e}")
            self.log.trace(f"Offending binary: {binary}")
            self.log.trace(traceback.format_exc())
        return error_sentinel

    async def _infinite_retry(self, callback, *args, **kwargs):
        interval = kwargs.pop("_interval", 300)
        context = kwargs.pop("_context", "")
        # default overall timeout of 10 minutes (300 second interval * 2 iterations)
        max_retries = kwargs.pop("_max_retries", 1)
        if not context:
            context = f"{callback.__name__}({args}, {kwargs})"
        retries = 0
        while not self._shutdown_status:
            try:
                return await asyncio.wait_for(callback(*args, **kwargs), timeout=interval)
            except (TimeoutError, asyncio.exceptions.TimeoutError):
                self.log.debug(f"{self.name}: Timeout after {interval:,} seconds {context}, retrying...")
                retries += 1
                if max_retries is not None and retries > max_retries:
                    raise TimeoutError(f"Timed out after {(max_retries+1)*interval:,} seconds {context}")

    def engine_debug(self, *args, **kwargs):
        if self._engine_debug:
            self.log.trace(*args, **kwargs)


class EngineClient(EngineBase):
    """
    The client portion of BBOT's RPC Engine.

    To create an engine, you must create a subclass of this class and also
    define methods for each of your desired functions.

    Note that this only supports async functions. If you need to offload a synchronous function to another CPU, use BBOT's multiprocessing pool instead.

    Any CPU or I/O intense logic should be implemented in the EngineServer.

    These functions are typically stubs whose only job is to forward the arguments to the server.

    Functions with the same names should be defined on the EngineServer.

    The EngineClient must specify its associated server class via the `SERVER_CLASS` variable.

    Depending on whether your function is a generator, you will use either `run_and_return()`, or `run_and_yield`.

    Examples:
        >>> from bbot.core.engine import EngineClient
        >>>
        >>> class MyClient(EngineClient):
        >>>     SERVER_CLASS = MyServer
        >>>
        >>>     async def my_function(self, **kwargs)
        >>>         return await self.run_and_return("my_function", **kwargs)
        >>>
        >>>     async def my_generator(self, **kwargs):
        >>>         async for _ in self.run_and_yield("my_generator", **kwargs):
        >>>             yield _
    """

    SERVER_CLASS = None

    def __init__(self, debug=False, **kwargs):
        self.name = f"EngineClient {self.__class__.__name__}"
        super().__init__(debug=debug)
        self.process = None
        if self.SERVER_CLASS is None:
            raise ValueError(f"Must set EngineClient SERVER_CLASS, {self.SERVER_CLASS}")
        self.CMDS = dict(self.SERVER_CLASS.CMDS)
        for k, v in list(self.CMDS.items()):
            self.CMDS[v] = k
        self.socket_address = f"zmq_{rand_string(8)}.sock"
        self.socket_path = Path(tempfile.gettempdir()) / self.socket_address
        self.server_kwargs = kwargs.pop("server_kwargs", {})
        self._server_process = None
        self.context = zmq.asyncio.Context()
        self.context.setsockopt(zmq.LINGER, 0)
        self.sockets = set()

    def check_error(self, message):
        if isinstance(message, dict) and len(message) == 1 and "_e" in message:
            self.engine_debug(f"{self.name}: got error message: {message}")
            error, trace = message["_e"]
            error = self.ERROR_CLASS(error)
            error.engine_traceback = trace
            self.engine_debug(f"{self.name}: raising {error.__class__.__name__}")
            raise error
        return False

    async def run_and_return(self, command, *args, **kwargs):
        fn_str = f"{command}({args}, {kwargs})"
        self.engine_debug(f"{self.name}: executing run-and-return {fn_str}")
        if self._shutdown_status and not command == "_shutdown":
            self.log.verbose(f"{self.name} has been shut down and is not accepting new tasks")
            return
        async with self.new_socket() as socket:
            try:
                message = self.make_message(command, args=args, kwargs=kwargs)
                if message is error_sentinel:
                    return
                await socket.send(message)
                binary = await self._infinite_retry(socket.recv, _context=f"waiting for return value from {fn_str}")
            except BaseException:
                try:
                    await self.send_cancel_message(socket, fn_str)
                except Exception:
                    self.log.debug(f"{self.name}: {fn_str} failed to send cancel message after exception")
                    self.log.trace(traceback.format_exc())
                raise
        # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
        message = self.unpickle(binary)
        self.engine_debug(f"{self.name}: {fn_str} got return value: {message}")
        # error handling
        if self.check_error(message):
            return
        return message

    async def run_and_yield(self, command, *args, **kwargs):
        fn_str = f"{command}({args}, {kwargs})"
        self.engine_debug(f"{self.name}: executing run-and-yield {fn_str}")
        if self._shutdown_status:
            self.log.verbose("Engine has been shut down and is not accepting new tasks")
            return
        message = self.make_message(command, args=args, kwargs=kwargs)
        if message is error_sentinel:
            return
        async with self.new_socket() as socket:
            # TODO: synchronize server-side generator by limiting qsize
            # socket.setsockopt(zmq.RCVHWM, 1)
            # socket.setsockopt(zmq.SNDHWM, 1)
            await socket.send(message)
            while 1:
                try:
                    binary = await self._infinite_retry(
                        socket.recv, _context=f"waiting for new iteration from {fn_str}"
                    )
                    # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
                    message = self.unpickle(binary)
                    self.engine_debug(f"{self.name}: {fn_str} got iteration: {message}")
                    # error handling
                    if self.check_error(message) or self.check_stop(message):
                        break
                    yield message
                except (StopAsyncIteration, GeneratorExit) as e:
                    exc_name = e.__class__.__name__
                    self.engine_debug(f"{self.name}.{command} got {exc_name}")
                    try:
                        await self.send_cancel_message(socket, fn_str)
                    except Exception:
                        self.engine_debug(f"{self.name}.{command} failed to send cancel message after {exc_name}")
                        self.log.trace(traceback.format_exc())
                    break

    async def send_cancel_message(self, socket, context):
        """
        Send a cancel message and wait for confirmation from the server
        """
        # -1 == special "cancel" signal
        message = pickle.dumps({"c": -1})
        await self._infinite_retry(socket.send, message)
        while 1:
            response = await self._infinite_retry(
                socket.recv, _context=f"waiting for CANCEL_OK from {context}", _max_retries=4
            )
            response = pickle.loads(response)
            if isinstance(response, dict):
                response = response.get("m", "")
                if response == "CANCEL_OK":
                    break

    async def send_shutdown_message(self):
        async with self.new_socket() as socket:
            # -99 == special shutdown message
            message = pickle.dumps({"c": -99})
            with suppress(TimeoutError, asyncio.exceptions.TimeoutError):
                await asyncio.wait_for(socket.send(message), 0.5)
            with suppress(TimeoutError, asyncio.exceptions.TimeoutError):
                while 1:
                    response = await asyncio.wait_for(socket.recv(), 0.5)
                    response = pickle.loads(response)
                    if isinstance(response, dict):
                        response = response.get("m", "")
                        if response == "SHUTDOWN_OK":
                            break

    def check_stop(self, message):
        if isinstance(message, dict) and len(message) == 1 and "_s" in message:
            return True
        return False

    def make_message(self, command, args=None, kwargs=None):
        try:
            cmd_id = self.CMDS[command]
        except KeyError:
            raise KeyError(f'Command "{command}" not found. Available commands: {",".join(self.available_commands)}')
        message = {"c": cmd_id}
        if args:
            message["a"] = args
        if kwargs:
            message["k"] = kwargs
        return pickle.dumps(message)

    @property
    def available_commands(self):
        return [s for s in self.CMDS if isinstance(s, str)]

    def start_server(self):
        import multiprocessing

        process_name = multiprocessing.current_process().name
        if process_name == "MainProcess":
            kwargs = dict(self.server_kwargs)
            # if we're in tests, we use a single event loop to avoid weird race conditions
            # this allows us to more easily mock http, etc.
            if os.environ.get("BBOT_TESTING", "") == "True":
                kwargs["_loop"] = get_event_loop()
            kwargs["debug"] = self._engine_debug
            self.process = CORE.create_process(
                target=self.server_process,
                args=(
                    self.SERVER_CLASS,
                    self.socket_path,
                ),
                kwargs=kwargs,
                custom_name=f"BBOT {self.__class__.__name__}",
            )
            self.process.start()
            return self.process
        else:
            raise BBOTEngineError(
                f"Tried to start server from process {process_name}. Did you forget \"if __name__ == '__main__'?\""
            )

    @staticmethod
    def server_process(server_class, socket_path, **kwargs):
        try:
            loop = kwargs.pop("_loop", None)
            engine_server = server_class(socket_path, **kwargs)
            if loop is not None:
                future = asyncio.run_coroutine_threadsafe(engine_server.worker(), loop)
                future.result()
            else:
                asyncio.run(engine_server.worker())
        except (asyncio.CancelledError, KeyboardInterrupt, CancelledError):
            return
        except Exception:
            import traceback

            log = logging.getLogger("bbot.core.engine.server")
            log.critical(f"Unhandled error in {server_class.__name__} server process: {traceback.format_exc()}")

    @asynccontextmanager
    async def new_socket(self):
        if self._server_process is None:
            self._server_process = self.start_server()
            while not self.socket_path.exists():
                self.engine_debug(f"{self.name}: waiting for server process to start...")
                await asyncio.sleep(0.1)
        socket = self.context.socket(zmq.DEALER)
        socket.setsockopt(zmq.LINGER, 0)  # Discard pending messages immediately disconnect() or close()
        socket.setsockopt(zmq.SNDHWM, 0)  # Unlimited send buffer
        socket.setsockopt(zmq.RCVHWM, 0)  # Unlimited receive buffer
        socket.connect(f"ipc://{self.socket_path}")
        self.sockets.add(socket)
        try:
            yield socket
        finally:
            self.sockets.remove(socket)
            with suppress(Exception):
                socket.close()

    async def shutdown(self):
        if not self._shutdown_status:
            self._shutdown_status = True
            self.log.verbose(f"{self.name}: shutting down...")
            # send shutdown signal
            await self.send_shutdown_message()
            # then terminate context
            try:
                self.context.destroy(linger=0)
            except Exception:
                print(traceback.format_exc(), file=sys.stderr)
            try:
                self.context.term()
            except Exception:
                print(traceback.format_exc(), file=sys.stderr)
            # delete socket file on exit
            self.socket_path.unlink(missing_ok=True)


class EngineServer(EngineBase):
    """
    The server portion of BBOT's RPC Engine.

    Methods defined here must match the methods in your EngineClient.

    To use the functions, you must create mappings for them in the CMDS attribute, as shown below.

    Examples:
        >>> from bbot.core.engine import EngineServer
        >>>
        >>> class MyServer(EngineServer):
        >>>     CMDS = {
        >>>         0: "my_function",
        >>>         1: "my_generator",
        >>>     }
        >>>
        >>>     def my_function(self, arg1=None):
        >>>         await asyncio.sleep(1)
        >>>         return str(arg1)
        >>>
        >>>     def my_generator(self):
        >>>         for i in range(10):
        >>>             await asyncio.sleep(1)
        >>>             yield i
    """

    CMDS = {}

    def __init__(self, socket_path, debug=False):
        self.name = f"EngineServer {self.__class__.__name__}"
        super().__init__(debug=debug)
        self.engine_debug(f"{self.name}: finished setup 1 (_debug={self._engine_debug})")
        self.socket_path = socket_path
        self.client_id_var = contextvars.ContextVar("client_id", default=None)
        # task <--> client id mapping
        self.tasks = {}
        # child tasks spawned by main tasks
        self.child_tasks = {}
        self.engine_debug(f"{self.name}: finished setup 2 (_debug={self._engine_debug})")
        if self.socket_path is not None:
            # create ZeroMQ context
            self.context = zmq.asyncio.Context()
            # ROUTER socket can handle multiple concurrent requests
            self.socket = self.context.socket(zmq.ROUTER)
            self.socket.setsockopt(zmq.LINGER, 0)  # Discard pending messages immediately disconnect() or close()
            self.socket.setsockopt(zmq.SNDHWM, 0)  # Unlimited send buffer
            self.socket.setsockopt(zmq.RCVHWM, 0)  # Unlimited receive buffer
            # create socket file
            self.socket.bind(f"ipc://{self.socket_path}")
        self.engine_debug(f"{self.name}: finished setup 3 (_debug={self._engine_debug})")

    @contextlib.contextmanager
    def client_id_context(self, value):
        token = self.client_id_var.set(value)
        try:
            yield
        finally:
            self.client_id_var.reset(token)

    async def run_and_return(self, client_id, command_fn, *args, **kwargs):
        fn_str = f"{command_fn.__name__}({args}, {kwargs})"
        self.engine_debug(fn_str)
        with self.client_id_context(client_id):
            try:
                self.engine_debug(f"{self.name}: starting run-and-return {fn_str}")
                try:
                    result = await command_fn(*args, **kwargs)
                except BaseException as e:
                    if in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
                        log_fn = self.log.debug
                    else:
                        log_fn = self.log.error
                    error = f"{self.name}: error in {fn_str}: {e}"
                    trace = traceback.format_exc()
                    log_fn(error)
                    self.log.trace(trace)
                    result = {"_e": (error, trace)}
                finally:
                    self.tasks.pop(client_id, None)
                    self.engine_debug(f"{self.name}: sending response to {fn_str}: {result}")
                    await self.send_socket_multipart(client_id, result)
            except BaseException as e:
                self.log.critical(
                    f"Unhandled exception in {self.name}.run_and_return({client_id}, {command_fn}, {args}, {kwargs}): {e}"
                )
                self.log.critical(traceback.format_exc())
            finally:
                self.engine_debug(f"{self.name} finished run-and-return {fn_str}")

    async def run_and_yield(self, client_id, command_fn, *args, **kwargs):
        fn_str = f"{command_fn.__name__}({args}, {kwargs})"
        with self.client_id_context(client_id):
            try:
                self.engine_debug(f"{self.name}: starting run-and-yield {fn_str}")
                try:
                    async for _ in command_fn(*args, **kwargs):
                        self.engine_debug(f"{self.name}: sending iteration for {fn_str}: {_}")
                        await self.send_socket_multipart(client_id, _)
                except BaseException as e:
                    if in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
                        log_fn = self.log.debug
                    else:
                        log_fn = self.log.error
                    error = f"{self.name}: error in {fn_str}: {e}"
                    trace = traceback.format_exc()
                    log_fn(error)
                    self.log.trace(trace)
                    result = {"_e": (error, trace)}
                    await self.send_socket_multipart(client_id, result)
                finally:
                    self.engine_debug(f"{self.name}: reached end of run-and-yield iteration for {fn_str}")
                    # _s == special signal that means StopIteration
                    await self.send_socket_multipart(client_id, {"_s": None})
                    self.tasks.pop(client_id, None)
            except BaseException as e:
                self.log.critical(
                    f"Unhandled exception in {self.name}.run_and_yield({client_id}, {command_fn}, {args}, {kwargs}): {e}"
                )
                self.log.critical(traceback.format_exc())
            finally:
                self.engine_debug(f"{self.name}: finished run-and-yield {fn_str}")

    async def send_socket_multipart(self, client_id, message):
        try:
            message = pickle.dumps(message)
            await self._infinite_retry(self.socket.send_multipart, [client_id, message])
        except Exception as e:
            self.log.verbose(f"{self.name}: error sending ZMQ message: {e}")
            self.log.trace(traceback.format_exc())

    def check_error(self, message):
        if message is error_sentinel:
            return True

    async def worker(self):
        self.engine_debug(f"{self.name}: starting worker")
        try:
            while 1:
                client_id, binary = await self.socket.recv_multipart()
                message = self.unpickle(binary)
                self.engine_debug(f"{self.name} got message: {message}")
                if self.check_error(message):
                    continue

                cmd = message.get("c", None)
                if not isinstance(cmd, int):
                    self.log.warning(f"{self.name}: no command sent in message: {message}")
                    continue

                # -1 == cancel task
                if cmd == -1:
                    self.engine_debug(f"{self.name} got cancel signal")
                    await self.send_socket_multipart(client_id, {"m": "CANCEL_OK"})
                    await self.cancel_task(client_id)
                    continue

                # -99 == shutdown task
                if cmd == -99:
                    self.log.verbose(f"{self.name} got shutdown signal")
                    await self.send_socket_multipart(client_id, {"m": "SHUTDOWN_OK"})
                    await self._shutdown()
                    return

                args = message.get("a", ())
                if not isinstance(args, tuple):
                    self.log.warning(f"{self.name}: received invalid args of type {type(args)}, should be tuple")
                    continue
                kwargs = message.get("k", {})
                if not isinstance(kwargs, dict):
                    self.log.warning(f"{self.name}: received invalid kwargs of type {type(kwargs)}, should be dict")
                    continue

                command_name = self.CMDS[cmd]
                command_fn = getattr(self, command_name, None)

                if command_fn is None:
                    self.log.warning(f'{self.name} has no function named "{command_fn}"')
                    continue

                if inspect.isasyncgenfunction(command_fn):
                    self.engine_debug(f"{self.name}: creating run-and-yield coroutine for {command_name}()")
                    coroutine = self.run_and_yield(client_id, command_fn, *args, **kwargs)
                else:
                    self.engine_debug(f"{self.name}: creating run-and-return coroutine for {command_name}()")
                    coroutine = self.run_and_return(client_id, command_fn, *args, **kwargs)

                self.engine_debug(f"{self.name}: creating task for {command_name}() coroutine")
                task = asyncio.create_task(coroutine)
                self.tasks[client_id] = task, command_fn, args, kwargs
                self.engine_debug(f"{self.name}: finished creating task for {command_name}() coroutine")
        except BaseException as e:
            await self._shutdown()
            if not in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
                self.log.error(f"{self.name}: error in EngineServer worker: {e}")
                self.log.trace(traceback.format_exc())
        finally:
            self.engine_debug(f"{self.name}: finished worker()")

    async def _shutdown(self):
        if not self._shutdown_status:
            self.log.verbose(f"{self.name}: shutting down...")
            self._shutdown_status = True
            await self.cancel_all_tasks()
            context = getattr(self, "context", None)
            if context is not None:
                try:
                    context.destroy(linger=0)
                except Exception:
                    self.log.trace(traceback.format_exc())
                try:
                    context.term()
                except Exception:
                    self.log.trace(traceback.format_exc())
            self.log.verbose(f"{self.name}: finished shutting down")

    async def task_pool(self, fn, args_kwargs, threads=10, timeout=300, global_kwargs=None):
        if global_kwargs is None:
            global_kwargs = {}

        tasks = {}
        args_kwargs = list(args_kwargs)

        def new_task():
            if args_kwargs:
                kwargs = {}
                tracker = None
                args = args_kwargs.pop(0)
                if isinstance(args, (list, tuple)):
                    # you can specify a custom tracker value if you want
                    # this helps with correlating results
                    with suppress(ValueError):
                        args, kwargs, tracker = args
                    # or you can just specify args/kwargs
                    with suppress(ValueError):
                        args, kwargs = args

                if not isinstance(kwargs, dict):
                    raise ValueError(f"kwargs must be dict (got: {kwargs})")
                if not isinstance(args, (list, tuple)):
                    args = [args]

                task = self.new_child_task(fn(*args, **kwargs, **global_kwargs))
                tasks[task] = (args, kwargs, tracker)

        for _ in range(threads):  # Start initial batch of tasks
            new_task()

        while tasks:  # While there are tasks pending
            # Wait for the first task to complete
            finished = await self.finished_tasks(tasks, timeout=timeout)
            for task in finished:
                result = task.result()
                (args, kwargs, tracker) = tasks.pop(task)
                yield (args, kwargs, tracker), result
                new_task()

    def new_child_task(self, coro):
        """
        Create a new asyncio task, making sure to track it based on the client id.

        This allows the task to be automatically cancelled if its parent is cancelled.
        """
        client_id = self.client_id_var.get()
        task = asyncio.create_task(coro)

        if client_id:

            def remove_task(t):
                tasks = self.child_tasks.get(client_id, set())
                tasks.discard(t)
                if not tasks:
                    self.child_tasks.pop(client_id, None)

            task.add_done_callback(remove_task)

            try:
                self.child_tasks[client_id].add(task)
            except KeyError:
                self.child_tasks[client_id] = {task}

        return task

    async def finished_tasks(self, tasks, timeout=None):
        """
        Given a list of asyncio tasks, return the ones that are finished with an optional timeout
        """
        if tasks:
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=timeout)
                return done
            except BaseException as e:
                if isinstance(e, (TimeoutError, asyncio.exceptions.TimeoutError)):
                    self.log.warning(f"{self.name}: Timeout after {timeout:,} seconds in finished_tasks({tasks})")
                    for task in tasks:
                        task.cancel()
                else:
                    if not in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
                        self.log.error(f"{self.name}: Unhandled exception in finished_tasks({tasks}): {e}")
                        self.log.trace(traceback.format_exc())
                    raise
        return set()

    async def cancel_task(self, client_id):
        parent_task = self.tasks.pop(client_id, None)
        if parent_task is None:
            return
        parent_task, _cmd, _args, _kwargs = parent_task
        self.engine_debug(f"{self.name}: Cancelling client id {client_id} (task: {parent_task})")
        parent_task.cancel()
        child_tasks = self.child_tasks.pop(client_id, set())
        if child_tasks:
            self.engine_debug(f"{self.name}: Cancelling {len(child_tasks):,} child tasks for client id {client_id}")
            for child_task in child_tasks:
                child_task.cancel()

        for task in [parent_task] + list(child_tasks):
            await self._cancel_task(task)

    async def _cancel_task(self, task):
        try:
            await asyncio.wait_for(task, timeout=10)
        except (TimeoutError, asyncio.exceptions.TimeoutError):
            self.log.trace(f"{self.name}: Timeout cancelling task: {task}")
            return
        except (KeyboardInterrupt, asyncio.CancelledError):
            return
        except BaseException as e:
            self.log.error(f"Unhandled error in {task.get_coro().__name__}(): {e}")
            self.log.trace(traceback.format_exc())

    async def cancel_all_tasks(self):
        for client_id in list(self.tasks):
            await self.cancel_task(client_id)
        for client_id, tasks in self.child_tasks.items():
            for task in tasks:
                await self._cancel_task(task)
