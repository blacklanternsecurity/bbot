import json
import time
import logging
from asgiref.sync import async_to_sync
from channels.consumer import SyncConsumer, AsyncConsumer
from channels.generic.websocket import AsyncJsonWebsocketConsumer, JsonWebsocketConsumer
from channels.layers import get_channel_layer

log = logging.getLogger(__name__)


class EventConsumer(AsyncJsonWebsocketConsumer):
    groups = ["scan_results_group"]

    async def connect(self):
        if False and self.scope["user"].is_anonymous:
            log.debug("closing anonymous connection")
            log.debug(self.__dict__)
            await self.close()
        else:
            await self.accept()
            self.groups = set()
            engagement_id = self.scope["url_route"]["kwargs"]["pk"]
            self.groups.add(engagement_id)
            await self.channel_layer.group_add("scan_results_group", self.channel_name)
            resp = {"command": "do-the-thing.sh", "arguments": {"foo": "bar"}}
            await self.send(json.dumps(resp))

    async def receive_json(self, content):
        log.debug(f"EventConsumer.receive_json(): {content}")

    async def receive(self, text_data):
        log.debug(f"EventConsumer.receive(): {text_data}")

    async def event_update(self, content):
        log.debug(f"EventConsumer.send(): {content}")


#       await self.send(str(content))
