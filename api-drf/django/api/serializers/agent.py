import logging
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.agent import *

log = logging.getLogger(__name__)

class AgentSessionSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = AgentSession
        fields = ('id', 'agent')

class AgentSerializer(FlexFieldsModelSerializer):
    sessions = AgentSessionSerializer(many=True)
    class Meta:
        model = Agent
        fields = ('agent_id', 'username')

class MessageSerializer(serializers.Serializer):
    message = serializers.CharField()
