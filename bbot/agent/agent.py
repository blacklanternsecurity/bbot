import json
import asyncio
import logging
import traceback
import websockets
from omegaconf import OmegaConf

from . import messages
import bbot.core.errors
from bbot.scanner import Scanner
from bbot.scanner.dispatcher import Dispatcher
from bbot.core.helpers.misc import urlparse, split_host_port
from bbot.core.configurator.environ import prepare_environment

log = logging.getLogger("bbot.core.agent")


class Agent:
    def __init__(self, config):
        self.config = config
        prepare_environment(self.config)
        self.url = self.config.get("agent_url", "")
        self.parsed_url = urlparse(self.url)
        self.host, self.port = split_host_port(self.parsed_url.netloc)
        self.token = self.config.get("agent_token", "")
        self.scan = None
        self.task = None
        self._ws = None
        self._scan_lock = asyncio.Lock()

        self.dispatcher = Dispatcher()
        self.dispatcher.on_status = self.on_scan_status
        self.dispatcher.on_finish = self.on_scan_finish

    def setup(self):
        if not self.url:
            log.error(f"Must specify agent_url")
            return False
        if not self.token:
            log.error(f"Must specify agent_token")
            return False
        return True

    async def ws(self, rebuild=False):
        if self._ws is None or rebuild:
            kwargs = {"close_timeout": 0.5}
            if self.token:
                kwargs.update({"extra_headers": {"Authorization": f"Bearer {self.token}"}})
            verbs = ("Building", "Built")
            if rebuild:
                verbs = ("Rebuilding", "Rebuilt")
            url = f"{self.url}/control/"
            log.debug(f"{verbs[0]} websocket connection to {url}")
            while 1:
                try:
                    self._ws = await websockets.connect(url, **kwargs)
                    break
                except Exception as e:
                    log.error(f'Failed to establish websockets connection to URL "{url}": {e}')
                    log.trace(traceback.format_exc())
                    await asyncio.sleep(1)
            log.debug(f"{verbs[1]} websocket connection to {url}")
        return self._ws

    async def start(self):
        rebuild = False
        while 1:
            ws = await self.ws(rebuild=rebuild)
            rebuild = False
            try:
                message = await ws.recv()
                log.debug(f"Got message: {message}")
                try:
                    message = json.loads(message)
                    message = messages.Message(**message)

                    if message.command == "ping":
                        if self.scan is None:
                            await self.send({"conversation": str(message.conversation), "message_type": "pong"})
                            continue

                    command_type = getattr(messages, message.command, None)
                    if command_type is None:
                        log.warning(f'Invalid command: "{message.command}"')
                        continue

                    command_args = command_type(**message.arguments)
                    command_fn = getattr(self, message.command)
                    response = await self.err_handle(command_fn, **command_args.dict())
                    log.info(str(response))
                    await self.send({"conversation": str(message.conversation), "message": response})

                except json.decoder.JSONDecodeError as e:
                    log.warning(f'Failed to decode message "{message}": {e}')
                    log.trace(traceback.format_exc())
                    continue
            except Exception as e:
                log.debug(f"Error receiving message: {e}")
                log.debug(traceback.format_exc())
                await asyncio.sleep(1)
                rebuild = True

    async def send(self, message):
        rebuild = False
        while 1:
            try:
                ws = await self.ws(rebuild=rebuild)
                j = json.dumps(message)
                log.debug(f"Sending message of length {len(message)}")
                await ws.send(j)
                rebuild = False
                break
            except Exception as e:
                log.warning(f"Error sending message: {e}, retrying")
                log.trace(traceback.format_exc())
                await asyncio.sleep(1)
                # rebuild = True

    async def start_scan(self, scan_id, name=None, targets=[], modules=[], output_modules=[], config={}):
        async with self._scan_lock:
            if self.scan is None:
                log.success(
                    f"Starting scan with targets={targets}, modules={modules}, output_modules={output_modules}"
                )
                output_module_config = OmegaConf.create(
                    {"output_modules": {"websocket": {"url": f"{self.url}/scan/{scan_id}/", "token": self.token}}}
                )
                config = OmegaConf.create(config)
                config = OmegaConf.merge(self.config, config, output_module_config)
                output_modules = list(set(output_modules + ["websocket"]))
                scan = Scanner(
                    *targets,
                    scan_id=scan_id,
                    name=name,
                    modules=modules,
                    output_modules=output_modules,
                    config=config,
                    dispatcher=self.dispatcher,
                )
                self.task = asyncio.create_task(self._start_scan_task(scan))

                return {"success": f"Started scan", "scan_id": scan.id}
            else:
                msg = f"Scan {self.scan.id} already in progress"
                log.warning(msg)
                return {"error": msg, "scan_id": self.scan.id}

    async def _start_scan_task(self, scan):
        self.scan = scan
        try:
            await scan.async_start_without_generator()
        except bbot.core.errors.ScanError as e:
            log.error(f"Scan error: {e}")
            log.trace(traceback.format_exc())
        except Exception:
            log.critical(f"Encountered error: {traceback.format_exc()}")
            self.on_scan_status("FAILED", scan.id)
        finally:
            self.task = None

    async def stop_scan(self):
        log.warning("Stopping scan")
        try:
            async with self._scan_lock:
                if self.scan is None:
                    msg = "Scan not in progress"
                    log.warning(msg)
                    return {"error": msg}
                scan_id = str(self.scan.id)
                self.scan.stop()
                msg = f"Stopped scan {scan_id}"
                log.warning(msg)
                self.scan = None
                return {"success": msg, "scan_id": scan_id}
        except Exception as e:
            log.warning(f"Error while stopping scan: {e}")
            log.trace(traceback.format_exc())
        finally:
            self.scan = None
            self.task = None

    async def scan_status(self):
        async with self._scan_lock:
            if self.scan is None:
                msg = "Scan not in progress"
                log.warning(msg)
                return {"error": msg}
        return {"success": "Polled scan", "scan_status": self.scan.status}

    async def on_scan_status(self, status, scan_id):
        await self.send({"message_type": "scan_status_change", "status": str(status), "scan_id": scan_id})

    async def on_scan_finish(self, scan):
        self.scan = None
        self.task = None

    async def err_handle(self, callback, *args, **kwargs):
        try:
            return await callback(*args, **kwargs)
        except Exception as e:
            msg = f"Error in {callback.__qualname__}(): {e}"
            log.error(msg)
            log.trace(traceback.format_exc())
            return {"error": msg}
