import os
from omegaconf import OmegaConf

from . import files, args
from ...modules import get_modules

available_modules = get_modules()

modules_config = OmegaConf.create()
for module_name, module in available_modules.items():
    module_config = OmegaConf.create(getattr(module, "options", {}))
    modules_config[module_name] = module_config

config = OmegaConf.merge(
    # first, pull module defaults
    OmegaConf.create({"modules": modules_config}),
    # then look in .yaml files
    files.get_config(),
    # finally, pull from CLI arguments
    args.get_config(),
)

# handle HTTP proxy
http_proxy = config.get("http_proxy", "")
if http_proxy:
    os.environ["HTTP_PROXY"] = http_proxy
    os.environ["HTTPS_PROXY"] = http_proxy
