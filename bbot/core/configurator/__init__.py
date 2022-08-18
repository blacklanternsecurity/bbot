import os
import sys
from pathlib import Path
from omegaconf import OmegaConf

from . import files, args, environ
from ..errors import ConfigLoadError
from ...modules import module_loader
from ..helpers.misc import mkdir, error_and_exit, filter_dict, clean_dict

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

# ensure bbot.yml
if not files.config_filename.exists():
    print(f"[INFO] Creating BBOT config at {files.config_filename}")
    no_secrets_config = OmegaConf.to_object(config)
    no_secrets_config = clean_dict(no_secrets_config, "api_key", "username", "password", "token", fuzzy=True)
    OmegaConf.save(config=OmegaConf.create(no_secrets_config), f=str(files.config_filename))

# ensure secrets.yml
if not files.secrets_filename.exists():
    print(f"[INFO] Creating BBOT secrets at {files.secrets_filename}")
    secrets_only_config = OmegaConf.to_object(config)
    secrets_only_config = filter_dict(secrets_only_config, "api_key", "username", "password", "token", fuzzy=True)
    OmegaConf.save(config=OmegaConf.create(secrets_only_config), f=str(files.secrets_filename))

# if we're running in a virtual environment, make sure to include its /bin in PATH
if sys.prefix != sys.base_prefix:
    bin_dir = str(Path(sys.prefix) / "bin")
    if bin_dir not in os.environ["PATH"].split(":"):
        os.environ["PATH"] = f'{bin_dir}:{os.environ.get("PATH", "")}'

# ensure bbot_tools
bbot_tools = home / "tools"
os.environ["BBOT_TOOLS"] = str(bbot_tools)
os.environ["PATH"] = f'{bbot_tools}:{os.environ.get("PATH", "")}'
# ensure bbot_cache
bbot_cache = home / "cache"
os.environ["BBOT_CACHE"] = str(bbot_cache)
# ensure bbot_temp
bbot_temp = home / "temp"
os.environ["BBOT_TEMP"] = str(bbot_temp)
# ensure bbot_lib
bbot_lib = home / "lib"
os.environ["BBOT_LIB"] = str(bbot_lib)

# exchange certain options between CLI args and config
if args.cli_options is not None:
    # deps
    config["retry_deps"] = args.cli_options.retry_deps
    config["force_deps"] = args.cli_options.force_deps
    config["no_deps"] = args.cli_options.no_deps
    config["ignore_failed_deps"] = args.cli_options.ignore_failed_deps
    # debug
    config["debug"] = args.cli_options.debug
    if args.cli_options.output_dir:
        config["output_dir"] = args.cli_options.output_dir

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
