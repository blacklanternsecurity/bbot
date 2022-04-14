import logging
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer

from api.models.engagement import Engagement

log = logging.getLogger(__name__)

class EngagementSerializer(FlexFieldsModelSerializer):
    class Meta:
        model = Engagement
        fields = '__all__'
