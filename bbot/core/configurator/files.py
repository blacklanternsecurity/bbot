from pathlib import Path
from shutil import copyfile
from omegaconf import OmegaConf

from ..helpers.misc import mkdir
from ..errors import ConfigLoadError

config_dir = (Path.home() / ".config" / "bbot").resolve()
defaults_filename = (Path(__file__).parent.parent.parent / "defaults.yml").resolve()
defaults_destination = config_dir / "defaults.yml"
mkdir(config_dir)
copyfile(defaults_filename, defaults_destination)
config_filename = (config_dir / "bbot.yml").resolve()
secrets_filename = (config_dir / "secrets.yml").resolve()


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
