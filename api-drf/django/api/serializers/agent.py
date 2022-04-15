import uuid
import logging
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.agent import *

log = logging.getLogger(__name__)

AGENT_COMMANDS = [
    ('start_scan', 'Start Scan'),
    ('stop_scan', 'Stop Scan'),
    ('scan_status', 'Scan Status'),
]

class AgentSessionSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = AgentSession
        fields = ('id', 'agent', 'channel_name', 'url')

        expandable_fields = {
            'agent': ('api.serializers.agent.AgentSerializer'),
        }

class AgentSerializer(FlexFieldsModelSerializer, serializers.HyperlinkedModelSerializer):
    sessions = AgentSessionSerializer(many=True, read_only=True)
    class Meta:
        model = Agent
        fields = ('agent_id', 'username', 'sessions', 'connected')

AgentSessionSerializer.agent = AgentSerializer(read_only=True)

class MessageSerializer(serializers.Serializer):
    conversation = serializers.UUIDField(default=uuid.uuid4, read_only=True)
    command = serializers.ChoiceField(choices=AGENT_COMMANDS)
    arguments = serializers.JSONField(default=dict)

    def validate(self, data):
        if 'conversation' not in data:
            data['conversation'] = uuid.uuid4()

        if 'arguments' not in data or data['arguments'] is None:
            data['arguments'] = {}

        return super().validate(data)
