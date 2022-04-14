import os
import logging
from django.urls import re_path
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")
asgi_app = ASGIStaticFilesHandler(get_asgi_application())

from api.lib.websocket import EventConsumer

class TokenAuthMiddleware(BaseMiddleware):
    @database_sync_to_async
    def get_user(self, token_key):
        from django.contrib.auth.models import AnonymousUser
        from rest_framework.authtoken.models import Token
        from api.models.agent import Agent
        try:
            token = Token.objects.get(key=token_key)
            log.debug(f"User: {token.user}")
            return token.user
        except Token.DoesNotExist:
            log.debug(f"No token found: {token_key}")
            return AnonymousUser()
        except Agent.DoesNotExist:
            log.debug(f"No Agent object found for user")
            return AnonymousUser()

    async def __call__(self, scope, receive, send):
        from django.contrib.auth.models import AnonymousUser
        try:
            header_val = next(filter(lambda x: x[0] == b'authorization', scope['headers']))[1]
            token = header_val.split(b" ")[1].decode()
            log.debug(f"Token: {token}")
        except ValueError:
            token_key = None

        scope['user'] = AnonymousUser() if token is None else await self.get_user(token)
        return await super().__call__(scope, receive, send)


application = ProtocolTypeRouter(
    {
        "http": asgi_app,
        "websocket": TokenAuthMiddleware(
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
