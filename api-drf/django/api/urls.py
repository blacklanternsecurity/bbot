import logging
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from api.viewsets.agent import *
from api.viewsets.engagement import *

log = logging.getLogger(__name__)

router = routers.SimpleRouter()
router.register('agents', AgentViewSet)
router.register('sessions', AgentSessionViewSet)
router.register('engagements', EngagementViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls),
]

