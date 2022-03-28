import logging

from . import misc
from .misc import *
from . import regexes
from .dns import DNSHelper


log = logging.getLogger("bbot.core.helpers")


class Helpers:

    from .web import request, download

    def __init__(self, config):
        self.config = config
        self.dns = DNSHelper(config)

    def __getattr__(self, attr):
        """
        Allow static functions from .misc to be accessed via Helpers class
        """
        method = getattr(misc, attr, None)
        if method:
            return method
        else:
            return getattr(self.dns, attr)
