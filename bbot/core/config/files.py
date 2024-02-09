import sys
from pathlib import Path
from omegaconf import OmegaConf

from ..errors import ConfigLoadError
from ..helpers.logger import log_to_stderr

bbot_code_dir = Path(__file__).parent.parent.parent
config_dir = (Path.home() / ".config" / "bbot").resolve()
defaults_filename = (bbot_code_dir / "defaults.yml").resolve()
config_filename = (config_dir / "bbot.yml").resolve()
secrets_filename = (config_dir / "secrets.yml").resolve()


def _get_config(filename, name="config"):
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


def get_config():
    default_config = _get_config(defaults_filename, name="defaults")
    return OmegaConf.merge(
        default_config,
        _get_config(config_filename, name="config"),
        _get_config(secrets_filename, name="secrets"),
    )
