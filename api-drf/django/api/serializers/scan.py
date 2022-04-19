import logging
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.scan import *

log = logging.getLogger(__name__)


class ParentCampaignValidator:
    def __init__(self, data):
        campaign = data["campaign"]
        for target in data["targets"]:
            if target.campaign.id != campaign.id:
                raise serializers.ValidationError("Scan campaign and target campaign must be the same")


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

        validators = [ParentCampaignValidator]


class ScanModuleSerializer(FlexFieldsModelSerializer):
    scans = ScanSerializer(many=True, read_only=True)

    class Meta:
        model = ScanModule
        fields = ("id", "scans", "value")

        expandable_fields = {
            "scans": ("api.serializers.scan.ScanSerializer", {"many": True}),
        }


class ScanTargetSerializer(FlexFieldsModelSerializer):
    scans = ScanSerializer(many=True, read_only=True)

    class Meta:
        model = ScanTarget
        fields = ("id", "campaign", "scans", "value")

        expandable_fields = {
            "campaign": ("api.serializers.campaign.CampaignSerializer"),
            "scans": ("api.serializers.scan.ScanSerializer", {"many": True}),
        }
