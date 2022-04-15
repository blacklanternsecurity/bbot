import logging
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action

from api.serializers.agent import *

log = logging.getLogger(__name__)


class AgentViewSet(viewsets.ModelViewSet):
    serializer_class = AgentSerializer
    queryset = AgentSerializer.Meta.model.objects.all()
    lookup_field = "agent_id"

    def get_serializer_class(self):
        if self.action == "send":
            return MessageSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=["post"])
    def send(self, request, agent_id):
        sessions = AgentSession.objects.filter(agent__agent_id=agent_id)

        res = []
        for session in sessions:
            serializer = self.get_serializer_class()
            s = serializer(data=request.data)
            if s.is_valid():
                msg = s.data
                sent = session.send(msg)
                if sent is not None:
                    res.append({str(session.id): sent})
            else:
                log.warning(f"Invalid data passed to serializer class: {request.data}")

        if len(res):
            result = "".join(res)
        else:
            result = []
        return Response({"data": result})


class AgentSessionViewSet(viewsets.ModelViewSet):
    serializer_class = AgentSessionSerializer
    queryset = AgentSessionSerializer.Meta.model.objects.all()

    def get_serializer_class(self):
        if self.action == "send":
            return MessageSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=["post"])
    def send(self, request, pk):
        session = AgentSession.objects.get(id=pk)

        serializer = self.get_serializer_class()
        s = serializer(data=request.data)
        if s.is_valid():
            msg = s.data
            log.debug(f"Sending message: {msg}")
            result = session.send(msg)
        else:
            log.warning(f"Invalid data passed to serializer class: {request.data}")
        return Response({"data": str(type(result))})
