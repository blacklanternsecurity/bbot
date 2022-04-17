import logging
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.scan import *

log = logging.getLogger(__name__)


class ScanTargetSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = ScanTarget
        fields = ("id", "scan", "value")

        expandable_fields = {
            "scan": ("api.serializers.scan.ScanSerializer"),
        }


class ScanModuleSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = ScanModule
        fields = ("id", "scan", "value")

        expandable_fields = {
            "scan": ("api.serializers.scan.ScanSerializer"),
        }


class ScanSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Scan
        fields = ("id", "campaign", "agent", "name", "targets", "modules", "status")

        expandable_fields = {
            "campaign": ("api.serializers.campaign.CampaignSerializer"),
            "agent": ("api.serializers.agent.AgentSerializer"),
            "targets": ("api.serializers.scan.ScanTargetSerializer", {"many": True}),
            "modules": ("api.serializers.scan.ScanModuleSerializer", {"many": True}),
        }
