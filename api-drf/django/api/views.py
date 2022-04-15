import logging
from django.http import JsonResponse
from rest_framework import status

log = logging.getLogger(__name__)


def agent_send(request, agent_id):
    log.debug(agent_id)
