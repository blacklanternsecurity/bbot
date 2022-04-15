import uuid
import logging
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.scan import *

log = logging.getLogger(__name__)


class ScanSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Scan
        fields = ("id", "campaign", "name", "status")

        expandable_fields = {
            "campaign": ("api.serializers.campaign.CampaignSerializer"),
        }
