import json
import threading
import websocket
from time import sleep

from bbot.modules.output.base import BaseOutputModule


class Websocket(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to websockets"}
    options = {"url": "", "token": ""}
    options_desc = {"url": "Web URL", "token": "Authorization Bearer token"}

    def setup(self):
        self.url = self.config.get("url", "")
        if not self.url:
            self.warning("Must set URL")
            return False
        kwargs = {}
        self.token = self.config.get("token", "")
        if self.token:
            kwargs.update({"header": {"Authorization": f"Bearer {self.token}"}})
        self.ws = websocket.WebSocketApp(self.url, **kwargs)
        self.started = False
        return True

    def start_websocket(self):
        if not self.started:
            self.thread = threading.Thread(target=self._start_websocket, daemon=True)
            self.thread.start()
            self.started = True

    def _start_websocket(self):
        not_keyboardinterrupt = False
        while not self.scan.stopping:
            not_keyboardinterrupt = self.ws.run_forever()
            if not not_keyboardinterrupt:
                break
            sleep(1)

    def handle_event(self, event):
        self.start_websocket()
        event_json = event.json()
        self.send(event_json)

    def send(self, message):
        while self.ws is not None:
            try:
                self.ws.send(json.dumps(message))
                break
            except Exception as e:
                self.warning(f"Error sending message: {e}, retrying")
                sleep(1)
                continue

    def cleanup(self):
        self.ws.close()
        self.ws = None
