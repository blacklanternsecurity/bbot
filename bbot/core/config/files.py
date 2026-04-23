import sys
import yaml
from pathlib import Path

from .merge import deep_update
from ...logger import log_to_stderr
from ...errors import ConfigLoadError


bbot_code_dir = Path(__file__).parent.parent.parent


class BBOTConfigFiles:
    config_dir = (Path.home() / ".config" / "bbot").resolve()
    defaults_filename = (bbot_code_dir / "defaults.yml").resolve()
    config_filename = (config_dir / "bbot.yml").resolve()
    secrets_filename = (config_dir / "secrets.yml").resolve()

    def __init__(self, core):
        self.core = core

    def _get_config(self, filename, name="config") -> dict:
        filename = Path(filename).resolve()
        if not filename.exists():
            return {}
        try:
            with open(filename) as f:
                conf = yaml.safe_load(f) or {}
            if not isinstance(conf, dict):
                raise ConfigLoadError(
                    f"Error parsing config at {filename}: expected a YAML mapping at the top level, "
                    f"got {type(conf).__name__}"
                )
            cli_silent = any(x in sys.argv for x in ("-s", "--silent"))
            if __name__ == "__main__" and not cli_silent:
                log_to_stderr(f"Loaded {name} from {filename}")
            return conf
        except ConfigLoadError:
            raise
        except Exception as e:
            raise ConfigLoadError(f"Error parsing config at {filename}:\n\n{e}")

    def get_custom_config(self) -> dict:
        return deep_update(
            self._get_config(self.config_filename, name="config"),
            self._get_config(self.secrets_filename, name="secrets"),
        )

    def get_default_config(self) -> dict:
        return self._get_config(self.defaults_filename, name="defaults")
