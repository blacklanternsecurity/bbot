import os
import sys
from pathlib import Path
from omegaconf import OmegaConf
from contextlib import suppress

from . import files, args, environ
from ..errors import ConfigLoadError
from ...modules import module_loader
from ..helpers.logger import log_to_stderr
from ..helpers.misc import error_and_exit, filter_dict, clean_dict, match_and_exit, is_file

# cached sudo password
bbot_sudo_pass = None

modules_config = OmegaConf.create(
    {
        "modules": module_loader.configs(type="scan"),
        "output_modules": module_loader.configs(type="output"),
        "internal_modules": module_loader.configs(type="internal"),
    }
)

try:
    config = OmegaConf.merge(
        # first, pull module defaults
        modules_config,
        # then look in .yaml files
        files.get_config(),
        # finally, pull from CLI arguments
        args.get_config(),
    )
except ConfigLoadError as e:
    error_and_exit(e)


config = environ.prepare_environment(config)
default_config = OmegaConf.merge(files.default_config, modules_config)


sentinel = object()


def check_cli_args():
    for c in args.cli_config:
        if not is_file(c):
            c = c.split("=")[0].strip()
            v = OmegaConf.select(default_config, c, default=sentinel)
            if v is sentinel:
                from ...modules import module_loader

                modules_options = set()
                for module_options in module_loader.modules_options().values():
                    modules_options.update(set(o[0] for o in module_options))
                global_options = set(default_config.keys()) - {"modules", "output_modules"}
                all_options = global_options.union(modules_options)
                match_and_exit(c, all_options, msg="module option")


def ensure_config_files():
    secrets_strings = ["api_key", "username", "password", "token", "secret", "_id"]
    exclude_keys = ["modules", "output_modules", "internal_modules"]

    # ensure bbot.yml
    if not files.config_filename.exists():
        log_to_stderr(f"Creating BBOT config at {files.config_filename}")
        no_secrets_config = OmegaConf.to_object(default_config)
        no_secrets_config = clean_dict(
            no_secrets_config,
            *secrets_strings,
            fuzzy=True,
            exclude_keys=exclude_keys,
        )
        yaml = OmegaConf.to_yaml(no_secrets_config)
        yaml = "\n".join(f"# {line}" for line in yaml.splitlines())
        with open(str(files.config_filename), "w") as f:
            f.write(yaml)

    # ensure secrets.yml
    if not files.secrets_filename.exists():
        log_to_stderr(f"Creating BBOT secrets at {files.secrets_filename}")
        secrets_only_config = OmegaConf.to_object(default_config)
        secrets_only_config = filter_dict(
            secrets_only_config,
            *secrets_strings,
            fuzzy=True,
            exclude_keys=exclude_keys,
        )
        yaml = OmegaConf.to_yaml(secrets_only_config)
        yaml = "\n".join(f"# {line}" for line in yaml.splitlines())
        with open(str(files.secrets_filename), "w") as f:
            f.write(yaml)
        files.secrets_filename.chmod(0o600)
