import logging
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from api.views import list_modules
from api.viewsets.agent import *
from api.viewsets.campaign import *
from api.viewsets.scan import *

log = logging.getLogger(__name__)

router = routers.SimpleRouter()
router.register("agents", AgentViewSet)
router.register("sessions", AgentSessionViewSet)
router.register("campaigns", CampaignViewSet)
router.register("scans", ScanViewSet)
router.register("targets", ScanTargetViewSet)

urlpatterns = [
    path("api/", include(router.urls)),
    path("admin/", admin.site.urls),
    path("api/modules/", list_modules),
]
