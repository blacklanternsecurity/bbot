import os
import sys
from pathlib import Path
from omegaconf import OmegaConf

from . import files, args, environ
from ..errors import ConfigLoadError
from ...modules import module_loader
from ..helpers.misc import mkdir, error_and_exit

try:
    config = OmegaConf.merge(
        # first, pull module defaults
        OmegaConf.create(
            {
                "modules": module_loader.configs(type="scan"),
                "output_modules": module_loader.configs(type="output"),
                "internal_modules": module_loader.configs(type="internal"),
            }
        ),
        # then look in .yaml files
        files.get_config(),
        # finally, pull from CLI arguments
        args.get_config(),
    )
except ConfigLoadError as e:
    error_and_exit(e)

# ensure bbot_home
if not "home" in config:
    config["home"] = "~/.bbot"
home = Path(config["home"]).expanduser().resolve()
config["home"] = str(home)
# ensure bbot_tools
bbot_tools = home / "tools"
config["tools"] = str(bbot_tools)
os.environ["PATH"] = f"{bbot_tools}:" + os.environ.get("PATH", "")
# ensure bbot_cache
bbot_cache = home / "cache"
config["cache"] = str(bbot_cache)
# ensure bbot_temp
bbot_temp = home / "temp"
config["temp"] = str(bbot_temp)
# ensure bbot_lib
bbot_lib = home / "lib"
config["lib"] = str(bbot_lib)

# exchange certain options between CLI args and config
if args.cli_options is not None:
    # deps
    config["ignore_failed_deps"] = args.cli_options.ignore_failed_deps
    config["retry_deps"] = args.cli_options.retry_deps
    config["force_deps"] = args.cli_options.force_deps
    config["no_deps"] = args.cli_options.no_deps
    # debug
    config["debug"] = args.cli_options.debug
    # -oA
    if args.cli_options.output_all:
        if not "output_modules" in config:
            config["output_modules"] = {}
        for om_modname in ("human", "csv", "json"):
            if not om_modname in config["output_modules"]:
                config["output_modules"][om_modname] = {}
            if om_modname == "human":
                om_filext = "txt"
            else:
                om_filext = str(om_modname)
            om_filename = f"{args.cli_options.output_all}.{om_filext}"
            config["output_modules"][om_modname]["output_file"] = om_filename

# copy config to environment
bbot_environ = environ.flatten_config(config)
os.environ.update(bbot_environ)

# handle HTTP proxy
http_proxy = config.get("http_proxy", "")
if http_proxy:
    os.environ["HTTP_PROXY"] = http_proxy
    os.environ["HTTPS_PROXY"] = http_proxy

# export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:~/.bbot/lib/
os.environ["LD_LIBRARY_PATH"] = ":".join(os.environ.get("LD_LIBRARY_PATH", "").split(":") + [str(bbot_lib)]).strip(":")

# replace environment variables in preloaded modules
module_loader.find_and_replace(**os.environ)

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
