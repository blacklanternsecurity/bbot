import uuid
import logging
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404

from api.lib.encoders import UUIDEncoder
from api.serializers.scan import *

log = logging.getLogger(__name__)

class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    queryset = ScanSerializer.Meta.model.objects.all()
