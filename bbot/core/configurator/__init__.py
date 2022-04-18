import os
from omegaconf import OmegaConf

from . import files, args
from ...modules import get_modules
from ...modules.output import get_modules as get_output_modules

available_modules = get_modules()
available_output_modules = get_output_modules()

modules_config = OmegaConf.create()
for module_name, module in available_modules.items():
    module_config = OmegaConf.create(getattr(module, "options", {}))
    modules_config[module_name] = module_config

output_modules_config = OmegaConf.create()
for module_name, module in available_output_modules.items():
    module_config = OmegaConf.create(getattr(module, "options", {}))
    output_modules_config[module_name] = module_config

config = OmegaConf.merge(
    # first, pull module defaults
    OmegaConf.create({"modules": modules_config, "output_modules": output_modules_config}),
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

# ssl verification
import urllib3

urllib3.disable_warnings()
ssl_verify = config.get("ssl_verify", False)
if not ssl_verify:
    import requests
    import functools

    requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
    requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
    requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
    requests.request = functools.partial(requests.request, verify=False)
