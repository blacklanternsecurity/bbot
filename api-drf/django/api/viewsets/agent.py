import uuid
import logging
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404

from api.lib.encoders import UUIDEncoder
from api.serializers.agent import *

log = logging.getLogger(__name__)

class AgentViewSet(viewsets.ModelViewSet):
    serializer_class = AgentSerializer
    queryset = AgentSerializer.Meta.model.objects.all()
    lookup_field = 'agent_id'

class AgentSessionViewSet(viewsets.ModelViewSet):
    serializer_class = AgentSessionSerializer
    queryset = AgentSessionSerializer.Meta.model.objects.all()
    
    def get_serializer_class(self):
        if self.action == "send":
            return MessageSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['post'])
    def send(self, request, pk):
        session = AgentSession.objects.get(id=pk)

        serializer = self.get_serializer_class()
        s = serializer(data=request.data)
        if s.is_valid():
            msg = json.dumps(s.validated_data, cls=UUIDEncoder)
            log.debug(f"Sending message: {msg}")
            result = session.send(msg)
        return Response({"data": str(type(result))})
