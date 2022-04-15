import json
import logging
import threading
import websocket
from time import sleep
from omegaconf import OmegaConf

from . import messages
from bbot.scanner import Scanner
from bbot.scanner.dispatcher import Dispatcher

log = logging.getLogger("bbot.core.agent")


class Agent:
    def __init__(self, config):
        self.config = config
        self.url = self.config.get("agent_url", "")
        self.token = self.config.get("agent_token", "")
        self.scan = None
        self.thread = None
        self._scan_lock = threading.Lock()

        self.dispatcher = Dispatcher()
        self.dispatcher.on_status = self.on_scan_status
        self.dispatcher.on_finish = self.on_scan_finish

    def setup(self):
        websocket.enableTrace(True)
        if not self.url:
            log.error(f"Must specify agent_url")
            return False
        if not self.token:
            log.error(f"Must specify agent_token")
            return False
        self.ws = websocket.WebSocketApp(
            f"{self.url}/control/",
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={"Authorization": f"Bearer {self.token}"},
        )
        return True

    def start(self):
        not_keyboardinterrupt = False
        while 1:
            not_keyboardinterrupt = self.ws.run_forever()
            if not not_keyboardinterrupt:
                break
            sleep(1)

    def send(self, message):
        while 1:
            try:
                self.ws.send(json.dumps(message))
                break
            except Exception as e:
                log.warning(f"Error sending message: {e}, retrying")
                sleep(1)
                continue

    def on_message(self, ws, message):
        try:
            message = json.loads(message)
        except Exception as e:
            log.warning(f'Failed to JSON-decode message "{message}": {e}')
            return
        log.success(f"{message}")
        message = messages.Message(**message)
        try:
            command_type = getattr(messages, message.command)
        except AttributeError:
            log.warning(f'Invalid command: "{message.command}"')
        command_args = command_type(**message.arguments)
        command_fn = getattr(self, message.command)
        response = self.err_handle(command_fn, **command_args.dict())
        log.info(str(response))
        self.send({"conversation": str(message.conversation), "message": response})

    def on_error(self, ws, error):
        log.warning(f"on_error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        log.warning("Closed connection")

    def on_open(self, ws):
        log.success("Opened connection")

    def start_scan(self, scan_id="", targets=[], modules=[], output_modules=[], config={}):
        with self._scan_lock:
            if self.scan is None:
                log.success(
                    f"Starting scan with targets={targets}, modules={modules}, output_modules={output_modules}"
                )
                output_module_config = OmegaConf.create(
                    {
                        "output_modules": {
                            "websocket": {"url": f"{self.url}/scan/{scan_id}/", "token": self.token}
                        }
                    }
                )
                config = OmegaConf.create(config)
                config = OmegaConf.merge(self.config, config, output_module_config)
                output_modules = list(set(output_modules + ["websocket"]))
                self.scan = Scanner(
                    *targets,
                    scan_id=scan_id,
                    modules=modules,
                    output_modules=output_modules,
                    config=config,
                    dispatcher=self.dispatcher,
                )
                self.thread = threading.Thread(target=self.scan.start)
                self.thread.start()
                return {"success": f"Started scan", "scan_id": self.scan.id}
            else:
                msg = f"Scan {self.scan.id} already in progress"
                log.warning(msg)
                return {"error": msg, "scan_id": self.scan.id}

    def stop_scan(self):
        try:
            with self._scan_lock:
                if self.scan is None:
                    msg = "Scan not in progress"
                    log.warning(msg)
                    return {"error": msg}
                self.scan.stop(wait=True)
                msg = f"Stopped scan {self.scan.id}"
                log.warning(msg)
                scan_id = str(self.scan.id)
                self.scan = None
                return {"success": msg, "scan_id": scan_id}
        finally:
            self.scan = None
            self.thread = None

    def scan_status(self):
        with self._scan_lock:
            if self.scan is None:
                self.thread = None
                msg = "Scan not in progress"
                log.warning(msg)
                return {"error": msg}
        return {"success": "Polled scan", "scan_status": self.scan.status}

    def on_scan_status(self, status, scan_id):
        self.send({"status": str(status), "scan_id": scan_id})

    def on_scan_finish(self, scan):
        self.scan = None
        self.thread = None

    @staticmethod
    def err_handle(callback, *args, **kwargs):
        log.critical(f"{callback}, {args}, {kwargs}")
        try:
            return callback(*args, **kwargs)
        except Exception as e:
            msg = f"Error in Agent.{callback.__name__}: {e}"
            log.error(msg)
            import traceback

            log.debug(traceback.format_exc())
            return {"error": msg}
