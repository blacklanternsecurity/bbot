import os
import logging
from django.urls import re_path
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")
asgi_app = ASGIStaticFilesHandler(get_asgi_application())

from api.lib.websocket import EventConsumer

application = ProtocolTypeRouter(
    {
        "http": asgi_app,
        "websocket": AuthMiddlewareStack(
            URLRouter(
                [
                    re_path(r"^ws/(?P<pk>\S+)/$", EventConsumer.as_asgi()),
                ]
            )
        ),
    }
)

log = logging.getLogger(__name__)
log.debug("ASGI init done")
