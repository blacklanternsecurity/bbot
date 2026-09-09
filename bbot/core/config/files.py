import os
import sys
import yaml
import atexit
import shutil
import tempfile
from pathlib import Path

from .merge import deep_merge
from ...logger import log_to_stderr
from ...errors import ConfigLoadError


bbot_code_dir = Path(__file__).parent.parent.parent

# cached per-process so every BBOTConfigFiles in a run resolves to the same dir
_test_config_dir = None


def isolated_test_config_dir():
    """A throwaway config dir for tests, so we never read or write the user's
    real ~/.config/bbot. It's created fresh per run (so previous or concurrent
    runs can't interfere) and shared across the run's processes via an env var
    so spawned children resolve to the same dir."""
    global _test_config_dir
    if _test_config_dir is None:
        env_dir = os.environ.get("BBOT_TEST_CONFIG_DIR")
        if env_dir:
            _test_config_dir = Path(env_dir)
        else:
            _test_config_dir = Path(tempfile.mkdtemp(prefix="bbot_test_config_"))
            os.environ["BBOT_TEST_CONFIG_DIR"] = str(_test_config_dir)
            atexit.register(lambda: shutil.rmtree(_test_config_dir, ignore_errors=True))
    return _test_config_dir


class BBOTConfigFiles:
    defaults_filename = (bbot_code_dir / "defaults.yml").resolve()

    def __init__(self, core):
        self.core = core
        if os.environ.get("BBOT_TESTING", "") == "True":
            base_dir = isolated_test_config_dir()
        else:
            base_dir = Path.home() / ".config" / "bbot"
        self.config_dir = base_dir.resolve()
        self.config_filename = (self.config_dir / "bbot.yml").resolve()
        self.secrets_filename = (self.config_dir / "secrets.yml").resolve()

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
        except yaml.YAMLError as e:
            raise ConfigLoadError(
                f"YAML syntax error in {filename}:\n\n{e}\n\nPlease check the file for indentation or formatting errors."
            )
        except Exception as e:
            raise ConfigLoadError(f"Error parsing config at {filename}:\n\n{e}")

    def get_custom_config(self) -> dict:
        return deep_merge(
            self._get_config(self.config_filename, name="config"),
            self._get_config(self.secrets_filename, name="secrets"),
        )

    def get_default_config(self) -> dict:
        return self._get_config(self.defaults_filename, name="defaults")
