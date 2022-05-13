import os
from pathlib import Path
from omegaconf import OmegaConf

from . import files, args, environ
from ...modules import output, internal, module_dir, modules_preloaded


all_modules_preloaded = {}
for p in modules_preloaded, output.modules_preloaded, internal.modules_preloaded:
    all_modules_preloaded.update(p)

available_modules = list(modules_preloaded)
modules_config = OmegaConf.create()
for module_name, preloaded in modules_preloaded.items():
    module_config = OmegaConf.create(preloaded.get("config", {}))
    modules_config[module_name] = module_config

available_output_modules = list(output.modules_preloaded)
output_modules_config = OmegaConf.create()
for module_name, preloaded in output.modules_preloaded.items():
    module_config = OmegaConf.create(preloaded.get("config", {}))
    output_modules_config[module_name] = module_config

config = OmegaConf.merge(
    # first, pull module defaults
    OmegaConf.create({"modules": modules_config, "output_modules": output_modules_config}),
    # then look in .yaml files
    files.get_config(),
    # finally, pull from CLI arguments
    args.get_config(),
)

# ensure bbot_home
if not "home" in config:
    config["home"] = "~/.bbot"
home = Path(config["home"]).expanduser().resolve()
config["home"] = str(home)
# ensure bbot_tools
bbot_tools = home / "tools"
bbot_tools.mkdir(exist_ok=True, parents=True)
config["tools"] = str(bbot_tools)
os.environ["PATH"] = f"{bbot_tools}:" + os.environ.get("PATH", "")
# ensure bbot_cache
bbot_cache = home / "cache"
bbot_cache.mkdir(exist_ok=True, parents=True)
config["cache"] = str(bbot_cache)
# ensure bbot_temp
bbot_temp = home / "temp"
bbot_temp.mkdir(exist_ok=True, parents=True)
config["temp"] = str(bbot_temp)

# copy certain args to config
if args.cli_options is not None:
    config["ignore_failed_deps"] = args.cli_options.ignore_failed_deps
    config["retry_deps"] = args.cli_options.retry_deps
    config["force_deps"] = args.cli_options.force_deps
    config["no_deps"] = args.cli_options.no_deps
    config["debug"] = args.cli_options.debug

# copy config to environment
os.environ.update(environ.flatten_config(config))

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
