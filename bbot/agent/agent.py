import rel
import json
import logging
import websocket

from . import messages

log = logging.getLogger("bbot.core.event")


class Agent:
    def __init__(self, config):
        self.config = config

    def setup(self):
        websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(
            self.config.agent_url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={"Authorization": f"Bearer {self.config.agent_token}"}
        )

    def start(self):
        self.ws.run_forever(dispatcher=rel)  # Set dispatcher to automatic reconnection
        rel.dispatch()

    def stop(self):
        rel.abort()

    def on_message(self, ws, message):
        try:
            message = json.loads(message)
        except Exception as e:
            log.warning(f'Failed to JSON-decode message "{message}"')
            return
        log.success(f"{message} ({type(message)})")


    def on_error(self, ws, error):
        log.error(error)

    def on_close(self, ws, close_status_code, close_msg):
        log.info("### closed ###")

    def on_open(self, ws):
        log.success("Opened connection")