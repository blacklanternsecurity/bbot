import os
import sys
from pathlib import Path
from omegaconf import OmegaConf

from . import files, args, environ
from ..errors import ConfigLoadError
from ...modules import module_loader
from ..helpers.misc import mkdir, error_and_exit, filter_dict, clean_dict, log_to_stderr

# cached sudo password
bbot_sudo_pass = None

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


config = environ.prepare_environment(config)


# ensure bbot.yml
if not files.config_filename.exists():
    log_to_stderr(f"Creating BBOT config at {files.config_filename}")
    no_secrets_config = OmegaConf.to_object(config)
    no_secrets_config = clean_dict(
        no_secrets_config,
        "api_key",
        "username",
        "password",
        "token",
        fuzzy=True,
        exclude_keys=["modules", "output_modules", "internal_modules"],
    )
    yaml = OmegaConf.to_yaml(no_secrets_config)
    yaml = "\n".join(f"# {line}" for line in yaml.splitlines())
    with open(str(files.config_filename), "w") as f:
        f.write(yaml)

# ensure secrets.yml
if not files.secrets_filename.exists():
    log_to_stderr(f"Creating BBOT secrets at {files.secrets_filename}")
    secrets_only_config = OmegaConf.to_object(config)
    secrets_only_config = filter_dict(
        secrets_only_config,
        "api_key",
        "username",
        "password",
        "token",
        "secret",
        "_id",
        fuzzy=True,
        exclude_keys=["modules", "output_modules", "internal_modules"],
    )
    yaml = OmegaConf.to_yaml(secrets_only_config)
    yaml = "\n".join(f"# {line}" for line in yaml.splitlines())
    with open(str(files.secrets_filename), "w") as f:
        f.write(yaml)
    files.secrets_filename.chmod(0o600)
