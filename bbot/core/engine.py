import zmq
import atexit
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
from bbot.core.helpers.misc import rand_string

CMD_EXIT = 1000


error_sentinel = object()


class EngineBase:
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

    def check_error(self, message):
        if message is error_sentinel:
            return True
        if isinstance(message, dict) and len(message) == 1 and "_e" in message:
            error, trace = message["_e"]
            self.log.error(error)
            self.log.trace(trace)
            return True
        return False


class EngineClient(EngineBase):

    SERVER_CLASS = None

    def __init__(self, **kwargs):
        super().__init__()
        self.name = f"EngineClient {self.__class__.__name__}"
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
        atexit.register(self.cleanup)

    async def run_and_return(self, command, **kwargs):
        async with self.new_socket() as socket:
            message = self.make_message(command, args=kwargs)
            if message is error_sentinel:
                return
            await socket.send(message)
            binary = await socket.recv()
        # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
        message = self.unpickle(binary)
        self.log.debug(f"{self.name}.{command}({kwargs}) got message: {message}")
        # error handling
        if self.check_error(message):
            return
        return message

    async def run_and_yield(self, command, **kwargs):
        message = self.make_message(command, args=kwargs)
        if message is error_sentinel:
            return
        async with self.new_socket() as socket:
            await socket.send(message)
            while 1:
                binary = await socket.recv()
                # self.log.debug(f"{self.name}.{command}({kwargs}) got binary: {binary}")
                message = self.unpickle(binary)
                self.log.debug(f"{self.name}.{command}({kwargs}) got message: {message}")
                # error handling
                if self.check_error(message) or self.check_stop(message):
                    break
                yield message

    def check_stop(self, message):
        if isinstance(message, dict) and len(message) == 1 and "_s" in message:
            return True
        return False

    def make_message(self, command, args):
        try:
            cmd_id = self.CMDS[command]
        except KeyError:
            raise KeyError(f'Command "{command}" not found. Available commands: {",".join(self.available_commands)}')
        return pickle.dumps(dict(c=cmd_id, a=args))

    @property
    def available_commands(self):
        return [s for s in self.CMDS if isinstance(s, str)]

    def start_server(self):
        process = CORE.create_process(
            target=self.server_process,
            args=(
                self.SERVER_CLASS,
                self.socket_path,
            ),
            kwargs=self.server_kwargs,
        )
        process.start()
        return process

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
        socket.connect(f"ipc://{self.socket_path}")
        try:
            yield socket
        finally:
            with suppress(Exception):
                socket.close()

    def cleanup(self):
        # delete socket file on exit
        self.socket_path.unlink(missing_ok=True)


class EngineServer(EngineBase):

    CMDS = {}

    def __init__(self, socket_path):
        super().__init__()
        self.name = f"EngineServer {self.__class__.__name__}"
        if socket_path is not None:
            # create ZeroMQ context
            self.context = zmq.asyncio.Context()
            # ROUTER socket can handle multiple concurrent requests
            self.socket = self.context.socket(zmq.ROUTER)
            # create socket file
            self.socket.bind(f"ipc://{socket_path}")

    async def run_and_return(self, client_id, command_fn, **kwargs):
        self.log.debug(f"{self.name} run-and-return {command_fn.__name__}({kwargs})")
        try:
            result = await command_fn(**kwargs)
        except Exception as e:
            error = f"Unhandled error in {self.name}.{command_fn.__name__}({kwargs}): {e}"
            trace = traceback.format_exc()
            result = {"_e": (error, trace)}
        await self.send_socket_multipart([client_id, pickle.dumps(result)])

    async def run_and_yield(self, client_id, command_fn, **kwargs):
        self.log.debug(f"{self.name} run-and-yield {command_fn.__name__}({kwargs})")
        try:
            async for _ in command_fn(**kwargs):
                await self.send_socket_multipart([client_id, pickle.dumps(_)])
            await self.send_socket_multipart([client_id, pickle.dumps({"_s": None})])
        except Exception as e:
            error = f"Unhandled error in {self.name}.{command_fn.__name__}({kwargs}): {e}"
            trace = traceback.format_exc()
            result = {"_e": (error, trace)}
            await self.send_socket_multipart([client_id, pickle.dumps(result)])

    async def send_socket_multipart(self, *args, **kwargs):
        try:
            await self.socket.send_multipart(*args, **kwargs)
        except Exception as e:
            self.log.warning(f"Error sending ZMQ message: {e}")
            self.log.trace(traceback.format_exc())

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

                kwargs = message.get("a", {})
                if not isinstance(kwargs, dict):
                    self.log.warning(f"{self.name}: received invalid message of type {type(kwargs)}, should be dict")
                    continue

                command_name = self.CMDS[cmd]
                command_fn = getattr(self, command_name, None)

                if command_fn is None:
                    self.log.warning(f'{self.name} has no function named "{command_fn}"')
                    continue

                if inspect.isasyncgenfunction(command_fn):
                    coroutine = self.run_and_yield(client_id, command_fn, **kwargs)
                else:
                    coroutine = self.run_and_return(client_id, command_fn, **kwargs)

                asyncio.create_task(coroutine)
        except Exception as e:
            self.log.error(f"Error in EngineServer worker: {e}")
            self.log.trace(traceback.format_exc())
        finally:
            with suppress(Exception):
                self.socket.close()
