import json
import uuid
import logging
from django.db import models
from django.contrib.auth.models import User

from asgiref.sync import async_to_sync

log = logging.getLogger(__name__)


class Agent(User):
    agent_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    @property
    def connected(self):
        return len(self.sessions.all()) > 0


class AgentSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel_name = models.CharField(editable=False, max_length=32)
    agent = models.ForeignKey("api.Agent", related_name="sessions", on_delete=models.CASCADE)

    def send(self, message):
        from api.lib.websocket import EventConsumer

        ec = EventConsumer()
        async_to_sync(ec.send_to_channel)(
            str(self.id), {"type": "dispatch_job", "data": json.dumps(message)}
        )
