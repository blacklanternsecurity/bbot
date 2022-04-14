import uuid
import logging
from rest_framework import viewsets

from api.serializers.engagement import *

log = logging.getLogger(__name__)


class EngagementViewSet(viewsets.ModelViewSet):
    serializer_class = EngagementSerializer
    queryset = EngagementSerializer.Meta.model.objects.all()
