import logging
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.campaign import Campaign

log = logging.getLogger(__name__)


class CampaignSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Campaign
        fields = "__all__"
