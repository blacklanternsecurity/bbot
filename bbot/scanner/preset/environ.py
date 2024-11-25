import os
import sys
import omegaconf
from pathlib import Path

from bbot.core.helpers.misc import cpu_architecture, os_platform, os_platform_friendly


REQUESTS_PATCHED = False


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


# Custom custom omegaconf resolver to get environment variables
def env_resolver(env_name, default=None):
    return os.getenv(env_name, default)


def add_to_path(v, k="PATH", environ=None):
    """
    Add an entry to a colon-separated PATH variable.
    If it's already contained in the value, shift it to be in first position.
    """
    if environ is None:
        environ = os.environ
    var_list = os.environ.get(k, "").split(":")
    deduped_var_list = []
    for _ in var_list:
        if _ != v and _ not in deduped_var_list:
            deduped_var_list.append(_)
    deduped_var_list = [v] + deduped_var_list
    new_var_str = ":".join(deduped_var_list).strip(":")
    environ[k] = new_var_str


# if we're running in a virtual environment, make sure to include its /bin in PATH
if sys.prefix != sys.base_prefix:
    bin_dir = str(Path(sys.prefix) / "bin")
    add_to_path(bin_dir)

# add ~/.local/bin to PATH
local_bin_dir = str(Path.home() / ".local" / "bin")
add_to_path(local_bin_dir)


# Register the new resolver
# this allows you to substitute environment variables in your config like "${env:PATH}""
omegaconf.OmegaConf.register_new_resolver("env", env_resolver)


class BBOTEnviron:
    def __init__(self, preset):
        self.preset = preset

    def flatten_config(self, config, base="bbot"):
        """
        Flatten a JSON-like config into a list of environment variables:
            {"modules": [{"httpx": {"timeout": 5}}]} --> "BBOT_MODULES_HTTPX_TIMEOUT=5"
        """
        if type(config) == omegaconf.dictconfig.DictConfig:
            for k, v in config.items():
                new_base = f"{base}_{k}"
                if type(v) == omegaconf.dictconfig.DictConfig:
                    yield from self.flatten_config(v, base=new_base)
                elif type(v) != omegaconf.listconfig.ListConfig:
                    yield (new_base.upper(), str(v))

    def prepare(self):
        """
        Sync config to OS environment variables
        """
        environ = dict(os.environ)

        # ensure bbot_tools
        environ["BBOT_TOOLS"] = str(self.preset.core.tools_dir)
        add_to_path(str(self.preset.core.tools_dir), environ=environ)
        # ensure bbot_cache
        environ["BBOT_CACHE"] = str(self.preset.core.cache_dir)
        # ensure bbot_temp
        environ["BBOT_TEMP"] = str(self.preset.core.temp_dir)
        # ensure bbot_lib
        environ["BBOT_LIB"] = str(self.preset.core.lib_dir)
        # export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:~/.bbot/lib/
        add_to_path(str(self.preset.core.lib_dir), k="LD_LIBRARY_PATH", environ=environ)

        # platform variables
        environ["BBOT_OS_PLATFORM"] = os_platform()
        environ["BBOT_OS"] = os_platform_friendly()
        environ["BBOT_CPU_ARCH"] = cpu_architecture()

        # copy config to environment
        bbot_environ = self.flatten_config(self.preset.config)
        environ.update(bbot_environ)

        # handle HTTP proxy
        http_proxy = self.preset.config.get("web", {}).get("http_proxy", "")
        if http_proxy:
            environ["HTTP_PROXY"] = http_proxy
            environ["HTTPS_PROXY"] = http_proxy
        else:
            environ.pop("HTTP_PROXY", None)
            environ.pop("HTTPS_PROXY", None)

        # ssl verification
        import urllib3

        urllib3.disable_warnings()
        ssl_verify = self.preset.config.get("ssl_verify", False)

        global REQUESTS_PATCHED
        if not ssl_verify and not REQUESTS_PATCHED:
            REQUESTS_PATCHED = True
            import requests
            import functools

            requests.adapters.BaseAdapter.send = functools.partialmethod(
                requests.adapters.BaseAdapter.send, verify=False
            )
            requests.adapters.HTTPAdapter.send = functools.partialmethod(
                requests.adapters.HTTPAdapter.send, verify=False
            )
            requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
            requests.request = functools.partial(requests.request, verify=False)

        return environ
