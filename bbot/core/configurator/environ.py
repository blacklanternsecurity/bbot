import os
import sys
import omegaconf
from pathlib import Path

from . import args
from ...modules import module_loader
from ..helpers.misc import cpu_architecture, os_platform, os_platform_friendly


def flatten_config(config, base="bbot"):
    """
    Flatten a JSON-like config into a list of environment variables:
        {"modules": [{"httpx": {"timeout": 5}}]} --> "BBOT_MODULES_HTTPX_TIMEOUT=5"
    """
    if type(config) == omegaconf.dictconfig.DictConfig:
        for k, v in config.items():
            new_base = f"{base}_{k}"
            if type(v) == omegaconf.dictconfig.DictConfig:
                yield from flatten_config(v, base=new_base)
            elif type(v) != omegaconf.listconfig.ListConfig:
                yield (new_base.upper(), str(v))


def prepare_environment(bbot_config):
    """
    Sync config to OS environment variables
    """
    # ensure bbot_home
    if not "home" in bbot_config:
        bbot_config["home"] = "~/.bbot"
    home = Path(bbot_config["home"]).expanduser().resolve()
    bbot_config["home"] = str(home)

    # if we're running in a virtual environment, make sure to include its /bin in PATH
    if sys.prefix != sys.base_prefix:
        bin_dir = str(Path(sys.prefix) / "bin")
        if bin_dir not in os.environ.get("PATH", "").split(":"):
            os.environ["PATH"] = f'{bin_dir}:{os.environ.get("PATH", "").strip(":")}'

    # ensure bbot_tools
    bbot_tools = home / "tools"
    os.environ["BBOT_TOOLS"] = str(bbot_tools)
    if not str(bbot_tools) in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = f'{bbot_tools}:{os.environ.get("PATH", "").strip(":")}'
    # ensure bbot_cache
    bbot_cache = home / "cache"
    os.environ["BBOT_CACHE"] = str(bbot_cache)
    # ensure bbot_temp
    bbot_temp = home / "temp"
    os.environ["BBOT_TEMP"] = str(bbot_temp)
    # ensure bbot_lib
    bbot_lib = home / "lib"
    os.environ["BBOT_LIB"] = str(bbot_lib)

    # platform variables
    os.environ["BBOT_OS_PLATFORM"] = os_platform()
    os.environ["BBOT_OS"] = os_platform_friendly()
    os.environ["BBOT_CPU_ARCH"] = cpu_architecture()

    # exchange certain options between CLI args and config
    if args.cli_options is not None:
        # deps
        bbot_config["retry_deps"] = args.cli_options.retry_deps
        bbot_config["force_deps"] = args.cli_options.force_deps
        bbot_config["no_deps"] = args.cli_options.no_deps
        bbot_config["ignore_failed_deps"] = args.cli_options.ignore_failed_deps
        # debug
        bbot_config["debug"] = args.cli_options.debug
        bbot_config["silent"] = args.cli_options.silent
        if args.cli_options.output_dir:
            bbot_config["output_dir"] = args.cli_options.output_dir

    # copy config to environment
    bbot_environ = flatten_config(bbot_config)
    os.environ.update(bbot_environ)

    # handle HTTP proxy
    http_proxy = bbot_config.get("http_proxy", "")
    if http_proxy:
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ["HTTPS_PROXY"] = http_proxy

    # export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:~/.bbot/lib/
    os.environ["LD_LIBRARY_PATH"] = ":".join(os.environ.get("LD_LIBRARY_PATH", "").split(":") + [str(bbot_lib)]).strip(
        ":"
    )

    # replace environment variables in preloaded modules
    module_loader.find_and_replace(**os.environ)

    # ssl verification
    import urllib3

    urllib3.disable_warnings()
    ssl_verify = bbot_config.get("ssl_verify", False)
    if not ssl_verify:
        import requests
        import functools

        requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
        requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
        requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
        requests.request = functools.partial(requests.request, verify=False)

    return bbot_config
