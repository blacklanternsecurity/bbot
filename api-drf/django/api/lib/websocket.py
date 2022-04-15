import logging
from channels.layers import get_channel_layer
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from api.models.agent import Agent, AgentSession

log = logging.getLogger(__name__)


class BaseConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        if self.scope["user"].is_anonymous:
            log.debug("closing anonymous connection")
            await self.close()
            return None
        else:
            await self.accept()
            self.groups = set()
            url_params = self.scope["url_route"]["kwargs"]
            log.debug(url_params)
            return url_params

    async def disconnect(self, close_code):
        log.debug(f"Disconnected: {close_code}")
        await self.delete_session()

    async def receive_json(self, content):
        log.debug(f"EventConsumer.receive_json(): {content}")

    async def receive(self, text_data):
        log.debug(f"EventConsumer.receive(): {text_data}")

    async def event_update(self, content):
        log.debug(f"EventConsumer.send(): {content}")


#       await self.send(str(content))


class AgentStatusConsumer(BaseConsumer):
    async def connect(self):
        url_params = await super().connect()
        log.debug("AgentStatusConsumer connected")
        if url_params is None:
            return


class EventConsumer(BaseConsumer):
    groups = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @database_sync_to_async
    def store_session(self):
        log.debug(f"Storing session object for {self.channel_name}")
        agent = Agent.objects.get(pk=self.scope["user"].id)
        session = AgentSession.objects.create(channel_name=self.channel_name, agent=agent)
        return session

    @database_sync_to_async
    def delete_session(self):
        log.debug(f"Removing session object for {self.channel_name}")
        agent = Agent.objects.get(pk=self.scope["user"].id)
        AgentSession.objects.filter(channel_name=self.channel_name, agent=agent).delete()

    async def connect(self):
        url_params = await super().connect()
        if url_params is None:
            return

        channel_type = url_params["channel_type"]
        if channel_type == "control":
            session = await self.store_session()
            await self.channel_layer.group_add(str(session.id), self.channel_name)
        elif channel_type == "scan":
            scan_id = url_params["pk"]
            log.debug(f"scan_id: {scan_id}")

        log.debug(f"Opened {channel_type} channel {self.channel_name}")

    async def send_to_channel(self, session_id, data):
        res = await get_channel_layer().group_send(session_id, data)
        log.debug("sent")
        return res

    async def dispatch_job(self, event):
        res = await self.send(event["data"])
        log.debug(f"Sent: {res}")
        return res
