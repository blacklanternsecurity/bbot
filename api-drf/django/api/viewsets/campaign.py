import logging
from rest_framework import viewsets

from api.serializers.campaign import *

log = logging.getLogger(__name__)


class CampaignViewSet(viewsets.ModelViewSet):
    serializer_class = CampaignSerializer
    queryset = CampaignSerializer.Meta.model.objects.all()
