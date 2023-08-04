import os
import sys
import omegaconf
from pathlib import Path

from . import args
from ...modules import module_loader
from ..helpers.misc import cpu_architecture, os_platform, os_platform_friendly


# keep track of whether BBOT is being executed via the CLI
cli_execution = False


def increase_limit(new_limit):
    try:
        import resource

        # Get current limit
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)

        new_limit = min(new_limit, hard_limit)

        # Attempt to set new limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard_limit))
    except Exception as e:
        sys.stderr.write(f"Failed to set new ulimit: {e}\n")


increase_limit(65535)


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


def add_to_path(v, k="PATH"):
    var_list = os.environ.get(k, "").split(":")
    deduped_var_list = []
    for _ in var_list:
        if not _ in deduped_var_list:
            deduped_var_list.append(_)
    if not v in deduped_var_list:
        deduped_var_list = [v] + deduped_var_list
    new_var_str = ":".join(deduped_var_list)
    os.environ[k] = new_var_str


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
        add_to_path(bin_dir)

    # add ~/.local/bin to PATH
    local_bin_dir = str(Path.home() / ".local" / "bin")
    add_to_path(local_bin_dir)

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
    # export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:~/.bbot/lib/
    add_to_path(str(bbot_lib), k="LD_LIBRARY_PATH")

    # platform variables
    os.environ["BBOT_OS_PLATFORM"] = os_platform()
    os.environ["BBOT_OS"] = os_platform_friendly()
    os.environ["BBOT_CPU_ARCH"] = cpu_architecture()

    # exchange certain options between CLI args and config
    if cli_execution and args.cli_options is not None:
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

    import logging

    log = logging.getLogger()
    if bbot_config.get("debug", False):
        bbot_config["silent"] = False
        log = logging.getLogger("bbot")
        log.setLevel(logging.DEBUG)
        logging.getLogger("asyncio").setLevel(logging.DEBUG)
    elif bbot_config.get("silent", False):
        log = logging.getLogger("bbot")
        log.setLevel(logging.CRITICAL)

    # copy config to environment
    bbot_environ = flatten_config(bbot_config)
    os.environ.update(bbot_environ)

    # handle HTTP proxy
    http_proxy = bbot_config.get("http_proxy", "")
    if http_proxy:
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ["HTTPS_PROXY"] = http_proxy
    else:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("HTTPS_PROXY", None)

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
