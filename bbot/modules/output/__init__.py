from pathlib import Path
from ...core.helpers.modules import preload_modules

module_dir = Path(__file__).parent
modules_preloaded = preload_modules(module_dir)
