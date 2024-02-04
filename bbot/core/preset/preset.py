import omegaconf
from pathlib import Path
from omegaconf import OmegaConf

from . import files
from ..helpers.misc import mkdir


class Preset(omegaconf.dictconfig.DictConfig):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # first, we load config files
        # this populates defaults and necessary stuff like:
        #    - bbot home directory
        #    - module load directories (needed for preloading modules)
        self.load_config_files()

        # next, we load environment variables
        # todo: automatically propagate config values to environ? (would require __setitem__ hooks)
        # self.load_environ()

        # next, we load module defaults
        # this populates valid modules + flags (needed for parsing CLI args)
        # self.load_module_configs()

        # finally, we parse CLI args
        # self.parse_cli_args()

    def load_config_files(self):
        self.update(files.get_config())

    def load_cli_args(self):
        pass
