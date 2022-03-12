import logging
from pathlib import Path
from omegaconf import OmegaConf

log = logging.getLogger("bbot.configurator.db")

config_filename = Path(__file__).parent.parent / "config.yaml"


def get_config():

    return OmegaConf.create({"database_test": "test"})
