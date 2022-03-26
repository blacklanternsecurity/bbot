import logging
from .misc import *
from . import regexes

log = logging.getLogger("bbot.core.helpers")


class Helpers:

    from . import misc
    from .web import request, download

    def __init__(self, config):
        self.config = config

    def __getattr__(self, attr):
        """
        Allow static functions from .misc to be accessed via Helpers class
        """
        return getattr(misc, attr)
