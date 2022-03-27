import logging
from . import dns
from . import misc
from .misc import *
from . import regexes
from .web import request, download


log = logging.getLogger("bbot.core.helpers")


class Helpers:
    def __init__(self, config):
        self.config = config

    def __getattr__(self, attr):
        """
        Allow static functions from .misc to be accessed via Helpers class
        """
        method = getattr(misc, attr, None)
        if method:
            return method
        else:
            return getattr(dns, attr)
