import uuid
import logging
from django.db import models
from asgiref.sync import async_to_sync
from django.contrib.auth.models import User

log = logging.getLogger(__name__)


class Agent(User):
    agent_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    from api.models.campaign import Campaign

    campaigns = models.ManyToManyField(Campaign, related_name="agents")

    @property
    def connected(self):
        return len(self.sessions.all()) > 0


class AgentSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel_name = models.CharField(editable=False, max_length=32)
    agent = models.ForeignKey("api.Agent", related_name="sessions", on_delete=models.CASCADE)

    def __get_consumer(self):
        from api.lib.websocket import ChannelManager

        manager = ChannelManager.get_channel_manager()
        ec = manager.retrieve(str(self.id))
        return ec

    def send(self, message, callback=None):
        from api.lib.websocket import EventConsumer

        ec = EventConsumer()
        async_to_sync(ec.send_to_channel)(str(self.id), message, callback)

    def ping(self, callback=None):
        ec = self.__get_consumer()
        if ec is not None:
            async_to_sync(ec.ping)(callback)
