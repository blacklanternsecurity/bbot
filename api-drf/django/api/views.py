import logging
from django.http import JsonResponse

log = logging.getLogger(__name__)

import bbot


def list_modules(request):
    modules = list(bbot.modules.get_modules().keys())
    return JsonResponse({"modules": modules})
