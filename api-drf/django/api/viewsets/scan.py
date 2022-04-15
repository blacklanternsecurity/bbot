import logging
from rest_framework import viewsets

from api.serializers.scan import *

log = logging.getLogger(__name__)


class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    queryset = ScanSerializer.Meta.model.objects.all()
