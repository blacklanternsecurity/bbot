import sys
from pathlib import Path
from omegaconf import OmegaConf

from ..errors import ConfigLoadError
from ..helpers.logger import log_to_stderr
from ..helpers.misc import mkdir, clean_dict, filter_dict


bbot_code_dir = Path(__file__).parent.parent.parent


class BBOTConfigFiles:

    config_dir = (Path.home() / ".config" / "bbot").resolve()
    defaults_filename = (bbot_code_dir / "defaults.yml").resolve()
    config_filename = (config_dir / "bbot.yml").resolve()
    secrets_filename = (config_dir / "secrets.yml").resolve()

    def __init__(self, core):
        self.core = core

    def ensure_config_files(self):
        mkdir(self.config_dir)

        secrets_strings = ["api_key", "username", "password", "token", "secret", "_id"]
        exclude_keys = ["modules", "output_modules", "internal_modules"]

        comment_notice = (
            "# NOTICE: THESE ENTRIES ARE COMMENTED BY DEFAULT\n"
            + "# Please be sure to uncomment when inserting API keys, etc.\n"
        )

        # ensure bbot.yml
        if not self.config_filename.exists():
            log_to_stderr(f"Creating BBOT config at {self.config_filename}")
            no_secrets_config = OmegaConf.to_object(self.core.default_config)
            no_secrets_config = clean_dict(
                no_secrets_config,
                *secrets_strings,
                fuzzy=True,
                exclude_keys=exclude_keys,
            )
            yaml = OmegaConf.to_yaml(no_secrets_config)
            yaml = comment_notice + "\n".join(f"# {line}" for line in yaml.splitlines())
            with open(str(self.config_filename), "w") as f:
                f.write(yaml)

        # ensure secrets.yml
        if not self.secrets_filename.exists():
            log_to_stderr(f"Creating BBOT secrets at {self.secrets_filename}")
            secrets_only_config = OmegaConf.to_object(self.core.default_config)
            secrets_only_config = filter_dict(
                secrets_only_config,
                *secrets_strings,
                fuzzy=True,
                exclude_keys=exclude_keys,
            )
            yaml = OmegaConf.to_yaml(secrets_only_config)
            yaml = comment_notice + "\n".join(f"# {line}" for line in yaml.splitlines())
            with open(str(self.secrets_filename), "w") as f:
                f.write(yaml)
            self.secrets_filename.chmod(0o600)

    def _get_config(self, filename, name="config"):
        filename = Path(filename).resolve()
        try:
            conf = OmegaConf.load(str(filename))
            cli_silent = any(x in sys.argv for x in ("-s", "--silent"))
            if __name__ == "__main__" and not cli_silent:
                log_to_stderr(f"Loaded {name} from {filename}")
            return conf
        except Exception as e:
            if filename.exists():
                raise ConfigLoadError(f"Error parsing config at {filename}:\n\n{e}")
            return OmegaConf.create()

    def get_custom_config(self):
        return OmegaConf.merge(
            self._get_config(self.config_filename, name="config"),
            self._get_config(self.secrets_filename, name="secrets"),
        )

    def get_default_config(self):
        return self._get_config(self.defaults_filename, name="defaults")
