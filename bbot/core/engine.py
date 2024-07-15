import zmq
import pickle
import asyncio
import inspect
import logging
import tempfile
import traceback
import zmq.asyncio
from pathlib import Path
from contextlib import asynccontextmanager, suppress

from bbot.core import CORE
from bbot.errors import BBOTEngineError
from bbot.core.helpers.misc import rand_string


error_sentinel = object()


class EngineBase:
    """
    Base Engine class for Server and Client.

    An Engine is a simple and lightweight RPC implementation that allows offloading async tasks
    to a separate process. It leverages ZeroMQ in a ROUTER-DEALER configuration.

    BBOT makes use of this by spawning a dedicated engine for DNS and HTTP tasks.
    This offloads I/O and helps free up the main event loop for other tasks.

    To use of Engine, you must subclass both EngineClient and EngineServer.

    See the respective EngineClient and EngineServer classes for usage examples.
    """

    ERROR_CLASS = BBOTEngineError

    def __init__(self):
        self.log = logging.getLogger(f"bbot.core.{self.__class__.__name__.lower()}")

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

    def __init__(self, **kwargs):
        self._shutdown = False
        super().__init__()
        self.name = f"EngineClient {self.__class__.__name__}"
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
            error, trace = message["_e"]
            error = self.ERROR_CLASS(error)
            error.engine_traceback = trace
            raise error
        return False

    async def run_and_return(self, command, *args, **kwargs):
        if self._shutdown:
            self.log.verbose("Engine has been shut down and is not accepting new tasks")
            return
        async with self.new_socket() as socket:
            try:
                message = self.make_message(command, args=args, kwargs=kwargs)
                if message is error_sentinel:
                    return
                await socket.send(message)
                binary = await socket.recv()
            except BaseException:
                # -1 == special "cancel" signal
                cancel_message = pickle.dumps({"c": -1})
                with suppress(Exception):
                    await socket.send(cancel_message)
                raise
        # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
        message = self.unpickle(binary)
        self.log.debug(f"{self.name}.{command}({kwargs}) got message: {message}")
        # error handling
        if self.check_error(message):
            return
        return message

    async def run_and_yield(self, command, *args, **kwargs):
        if self._shutdown:
            self.log.verbose("Engine has been shut down and is not accepting new tasks")
            return
        message = self.make_message(command, args=args, kwargs=kwargs)
        if message is error_sentinel:
            return
        async with self.new_socket() as socket:
            await socket.send(message)
            while 1:
                try:
                    binary = await socket.recv()
                    # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
                    message = self.unpickle(binary)
                    self.log.debug(f"{self.name}.{command}({kwargs}) got message: {message}")
                    # error handling
                    if self.check_error(message) or self.check_stop(message):
                        break
                    yield message
                except GeneratorExit:
                    # -1 == special "cancel" signal
                    cancel_message = pickle.dumps({"c": -1})
                    with suppress(Exception):
                        await socket.send(cancel_message)
                    raise

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
            self.process = CORE.create_process(
                target=self.server_process,
                args=(
                    self.SERVER_CLASS,
                    self.socket_path,
                ),
                kwargs=self.server_kwargs,
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
            engine_server = server_class(socket_path, **kwargs)
            asyncio.run(engine_server.worker())
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        except Exception:
            import traceback

            log = logging.getLogger("bbot.core.engine.server")
            log.critical(f"Unhandled error in {server_class.__name__} server process: {traceback.format_exc()}")

    @asynccontextmanager
    async def new_socket(self):
        if self._server_process is None:
            self._server_process = self.start_server()
            while not self.socket_path.exists():
                await asyncio.sleep(0.1)
        socket = self.context.socket(zmq.DEALER)
        socket.setsockopt(zmq.LINGER, 0)
        socket.connect(f"ipc://{self.socket_path}")
        self.sockets.add(socket)
        try:
            yield socket
        finally:
            self.sockets.remove(socket)
            with suppress(Exception):
                socket.close()

    async def shutdown(self):
        if not self._shutdown:
            self._shutdown = True
            async with self.new_socket() as socket:
                # -99 == special shutdown signal
                shutdown_message = pickle.dumps({"c": -99})
                try:
                    await asyncio.wait_for(socket.send(shutdown_message), timeout=.2)
                except (TimeoutError, asyncio.TimeoutError):
                    self.log.debug(f"Timeout sending shutdown message to {self.name} server")
            # allow shutdown signal .1 seconds to get delivered
            await asyncio.sleep(0.1)
            # then terminate context
            self.context.term()
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

    def __init__(self, socket_path):
        super().__init__()
        self.name = f"EngineServer {self.__class__.__name__}"
        self.socket_path = socket_path
        if self.socket_path is not None:
            # create ZeroMQ context
            self.context = zmq.asyncio.Context()
            self.context.setsockopt(zmq.LINGER, 0)
            # ROUTER socket can handle multiple concurrent requests
            self.socket = self.context.socket(zmq.ROUTER)
            self.socket.setsockopt(zmq.LINGER, 0)
            # create socket file
            self.socket.bind(f"ipc://{self.socket_path}")
            # task <--> client id mapping
            self.tasks = dict()

    async def run_and_return(self, client_id, command_fn, *args, **kwargs):
        try:
            self.log.debug(f"{self.name} run-and-return {command_fn.__name__}({args}, {kwargs})")
            try:
                result = await command_fn(*args, **kwargs)
            except (asyncio.CancelledError, KeyboardInterrupt):
                return
            except BaseException as e:
                error = f"Error in {self.name}.{command_fn.__name__}({args}, {kwargs}): {e}"
                trace = traceback.format_exc()
                self.log.debug(error)
                self.log.debug(trace)
                result = {"_e": (error, trace)}
            finally:
                self.tasks.pop(client_id, None)
            await self.send_socket_multipart(client_id, result)
        except BaseException as e:
            self.log.critical(
                f"Unhandled exception in {self.name}.run_and_return({client_id}, {command_fn}, {args}, {kwargs}): {e}"
            )
            self.log.critical(traceback.format_exc())

    async def run_and_yield(self, client_id, command_fn, *args, **kwargs):
        try:
            self.log.debug(f"{self.name} run-and-yield {command_fn.__name__}({args}, {kwargs})")
            try:
                async for _ in command_fn(*args, **kwargs):
                    await self.send_socket_multipart(client_id, _)
                await self.send_socket_multipart(client_id, {"_s": None})
            except (asyncio.CancelledError, KeyboardInterrupt):
                return
            except BaseException as e:
                error = f"Error in {self.name}.{command_fn.__name__}({args}, {kwargs}): {e}"
                trace = traceback.format_exc()
                self.log.debug(error)
                self.log.debug(trace)
                result = {"_e": (error, trace)}
                await self.send_socket_multipart(client_id, result)
            finally:
                self.tasks.pop(client_id, None)
        except BaseException as e:
            self.log.critical(
                f"Unhandled exception in {self.name}.run_and_yield({client_id}, {command_fn}, {args}, {kwargs}): {e}"
            )
            self.log.critical(traceback.format_exc())

    async def send_socket_multipart(self, client_id, message):
        try:
            message = pickle.dumps(message)
            await self.socket.send_multipart([client_id, message])
        except Exception as e:
            self.log.warning(f"Error sending ZMQ message: {e}")
            self.log.trace(traceback.format_exc())

    def check_error(self, message):
        if message is error_sentinel:
            return True

    async def worker(self):
        try:
            while 1:
                client_id, binary = await self.socket.recv_multipart()
                message = self.unpickle(binary)
                self.log.debug(f"{self.name} got message: {message}")
                if self.check_error(message):
                    continue

                cmd = message.get("c", None)
                if not isinstance(cmd, int):
                    self.log.warning(f"No command sent in message: {message}")
                    continue

                # -1 == cancel task
                if cmd == -1:
                    await self.cancel_task(client_id)
                    continue

                # -99 == shut down engine
                if cmd == -99:
                    self.log.verbose("Got shutdown signal, shutting down...")
                    await self.cancel_all_tasks()
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
                    coroutine = self.run_and_yield(client_id, command_fn, *args, **kwargs)
                else:
                    coroutine = self.run_and_return(client_id, command_fn, *args, **kwargs)

                task = asyncio.create_task(coroutine)
                self.tasks[client_id] = task, command_fn, args, kwargs
        except Exception as e:
            self.log.error(f"Error in EngineServer worker: {e}")
            self.log.trace(traceback.format_exc())
        finally:
            self.socket.close()
            self.context.term()
            # delete socket file on exit
            self.socket_path.unlink(missing_ok=True)

    async def cancel_task(self, client_id):
        task = self.tasks.get(client_id, None)
        if task is None:
            return
        task, _cmd, _args, _kwargs = task
        self.log.debug(f"Cancelling client id {client_id} (task: {task})")
        task.cancel()
        try:
            try:
                await asyncio.wait_for(task, timeout=.2)
            except (TimeoutError, asyncio.TimeoutError):
                self.log.debug(f"{self.name}: Timeout cancelling task")
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        except BaseException as e:
            self.log.error(f"Unhandled error in {_cmd}({_args}, {_kwargs}): {e}")
            self.log.trace(traceback.format_exc())
        finally:
            self.tasks.pop(client_id, None)

    async def cancel_all_tasks(self):
        for client_id in self.tasks:
            await self.cancel_task(client_id)
