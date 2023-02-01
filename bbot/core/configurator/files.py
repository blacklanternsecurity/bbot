from pathlib import Path
from omegaconf import OmegaConf

from ..helpers.misc import mkdir
from ..errors import ConfigLoadError
from ..helpers.logger import log_to_stderr

config_dir = (Path.home() / ".config" / "bbot").resolve()
defaults_filename = (Path(__file__).parent.parent.parent / "defaults.yml").resolve()
mkdir(config_dir)
config_filename = (config_dir / "bbot.yml").resolve()
secrets_filename = (config_dir / "secrets.yml").resolve()


def _get_config(filename, name="config", notify=True):
    filename = Path(filename).resolve()
    try:
        conf = OmegaConf.load(str(filename))
        if notify:
            log_to_stderr(f"Loaded {name} from {filename}")
        return conf
    except Exception as e:
        if filename.exists():
            raise ConfigLoadError(f"Error parsing config at {filename}:\n\n{e}")
        return OmegaConf.create()


def get_config():
    return OmegaConf.merge(
        _get_config(defaults_filename, name="defaults"),
        _get_config(config_filename, name="config"),
        _get_config(secrets_filename, name="secrets"),
    )
