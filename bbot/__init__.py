# version placeholder (replaced by poetry-dynamic-versioning)
__version__ = "0.0.0"

# global app config
from .core import configurator

config = configurator.config

# helpers
from .core import helpers
