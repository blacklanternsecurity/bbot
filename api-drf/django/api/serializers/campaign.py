import logging
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.campaign import Campaign

log = logging.getLogger(__name__)


class CampaignSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Campaign
        fields = ("id", "name", "agents", "scans", "url")

        expandable_fields = {
            "agents": ("api.serializers.agent.AgentSerializer", {"many": True}),
            "scans": ("api.serializers.scan.ScanSerializer", {"many": True}),
        }
