import importlib
from pathlib import Path

from .base import BaseCloudProvider

# dynamically load cloud provider modules
provider_list = []
for file in Path(__file__).parent.glob("*.py"):
    if not file.stem in ("base", "__init__"):
        import_path = f"bbot.core.helpers.cloud.{file.stem}"
        module_variables = importlib.import_module(import_path, "bbot")
        for variable in module_variables.__dict__.keys():
            value = getattr(module_variables, variable)
            if hasattr(value, "__mro__") and not value == BaseCloudProvider and BaseCloudProvider in value.__mro__:
                provider_list.append(value)


class CloudProviders:
    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.providers = {}
        for provider_class in provider_list:
            provider_name = str(provider_class.__name__).lower()
            provider = provider_class(self.parent_helper)
            self.providers[provider_name] = provider
            setattr(self, provider_name, provider)

    def excavate(self, event):
        for provider in self.providers.values():
            provider.excavate(event)

    def __iter__(self):
        yield from self.providers.values()
