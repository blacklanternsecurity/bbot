import sys
from pathlib import Path
from omegaconf import OmegaConf

from ..helpers.misc import mkdir
from ...errors import ConfigLoadError
from ..helpers.logger import log_to_stderr


bbot_code_dir = Path(__file__).parent.parent.parent


class BBOTConfigFiles:

    config_dir = (Path.home() / ".config" / "bbot").resolve()
    defaults_filename = (bbot_code_dir / "defaults.yml").resolve()
    config_filename = (config_dir / "bbot.yml").resolve()

    def __init__(self, core):
        self.core = core

    def ensure_config_file(self):
        mkdir(self.config_dir)

        comment_notice = (
            "# NOTICE: THESE ENTRIES ARE COMMENTED BY DEFAULT\n"
            + "# Please be sure to uncomment when inserting API keys, etc.\n"
        )

        # ensure bbot.yml
        if not self.config_filename.exists():
            log_to_stderr(f"Creating BBOT config at {self.config_filename}")
            yaml = OmegaConf.to_yaml(self.core.default_config)
            yaml = comment_notice + "\n".join(f"# {line}" for line in yaml.splitlines())
            with open(str(self.config_filename), "w") as f:
                f.write(yaml)

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
        return self._get_config(self.config_filename, name="config")

    def get_default_config(self):
        return self._get_config(self.defaults_filename, name="defaults")
