from pathlib import Path
from omegaconf import OmegaConf

from ..errors import ConfigLoadError

home_dir = Path(__file__).parent.parent.parent.parent
defaults_filename = (home_dir / "bbot" / "defaults.yml").resolve()
config_filename = (home_dir / "bbot.yml").resolve()
secrets_filename = (home_dir / "secrets.yml").resolve()


def _get_config(filename):
    filename = Path(filename).resolve()
    try:
        return OmegaConf.load(str(filename))
    except Exception as e:
        if filename.exists():
            raise ConfigLoadError(f"Error parsing config at {filename}:\n\n{e}")
        return OmegaConf.create()


def get_config():

    return OmegaConf.merge(
        _get_config(defaults_filename),
        _get_config(config_filename),
        _get_config(secrets_filename),
    )
