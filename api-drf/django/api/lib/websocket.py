import json
import uuid
import logging
import functools
from channels.layers import get_channel_layer
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from api.models.scan import Scan
from api.models.agent import Agent, AgentSession

log = logging.getLogger(__name__)
channel_manager = None


class ChannelManager:
    __channels = None

    @classmethod
    def get_channel_manager(cls):
        global channel_manager

        if channel_manager is None:
            channel_manager = cls()

        return channel_manager

    def __init__(self):
        self.__channels = {}

    def save(self, session, consumer):
        self.__channels[session] = consumer

    def retrieve(self, session):
        return self.__channels.get(session, None)


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


class AgentStatusConsumer(BaseConsumer):
    async def connect(self):
        url_params = await super().connect()
        log.debug("AgentStatusConsumer connected")
        if url_params is None:
            return


class EventConsumer(BaseConsumer):
    groups = []
    __agent = None
    __callbacks = None

    @classmethod
    def get_control_channel(cls, **initkwargs):
        global control_channel

        if control_channel is None:
            control_channel = cls(**initkwargs)

        return control_channel

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__callbacks = {}

    @property
    def agent(self):
        if self.__agent is None:
            self.__agent = Agent.objects.get(pk=self.scope["user"].id)
        return self.__agent

    @database_sync_to_async
    def store_session(self):
        log.debug(f"Storing session object for {self.channel_name}")
        session = AgentSession.objects.create(channel_name=self.channel_name, agent=self.agent)
        return session

    @database_sync_to_async
    def delete_session(self):
        log.debug(f"Removing session object for {self.channel_name}")
        AgentSession.objects.filter(channel_name=self.channel_name, agent=self.agent).delete()

    @database_sync_to_async
    def get_scan(self, scan_id):
        return self.agent.scans.get(pk=scan_id)

    async def connect(self):
        url_params = await super().connect()
        if url_params is None:
            return

        channel_type = url_params["channel_type"]
        if channel_type == "control":
            session = await self.store_session()
            manager = ChannelManager.get_channel_manager()
            manager.save(str(session.id), self)
            await self.channel_layer.group_add(str(session.id), self.channel_name)
        elif channel_type == "scan":
            scan_id = url_params["pk"]
            log.debug(f"scan_id: {scan_id}")

        log.debug(f"Opened {channel_type} channel {self.channel_name}")

    async def send_to_channel(self, session_id, data):
        res = await get_channel_layer().group_send(session_id, data)
        return res

    async def start_scan(self, event):
        res = await self.send(
            json.dumps(
                {
                    "command": "start_scan",
                    "conversation": str(uuid.uuid4()),
                    "arguments": event["data"],
                }
            )
        )
        log.debug(f"Sent: {res}")
        return res

    async def ping(self, callback=None):
        conversation = str(uuid.uuid4())
        if callback is not None:
            self.__callbacks[conversation] = callback
            log.debug(f"Registered callback for conversation {conversation}")

        data = json.dumps({"conversation": conversation, "command": "ping", "arguments": {}})
        res = await self.send(data)
        return res

    async def pong(self, event):
        conversation = event["conversation"]
        if conversation not in self.__callbacks.keys():
            log.warning(f"Received unregistered ping callback: {conversation}")
            log.debug(self.__callbacks.keys())
            return

        callback = self.__callbacks.pop(conversation)
        await callback(self)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if "message_type" not in data.keys():
                raise ValueError("No message_type specified in incoming message")
            elif data["message_type"] == "scan_status_change":
                scan = await self.get_scan(data["scan_id"])
                log.debug(scan)
            elif data["message_type"] == "pong":
                await self.pong(data)

        except Exception as e:
            log.debug(text_data)
            log.debug(e)
            log.debug(type(e))
