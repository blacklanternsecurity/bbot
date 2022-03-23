import os
import importlib
from pathlib import Path
from .base import BaseModule

module_dir = Path(__file__).parent
module_files = list(os.listdir(module_dir))


def list_module_stems():
    """
    Simpler function to list files only
    Avoids circular imports
    """

    for file in module_files:
        file = module_dir / file
        if (
            file.is_file()
            and file.suffix.lower() == ".py"
            and file.stem not in ["base", "__init__"]
        ):
            yield file.stem


def get_modules():
    available_modules = {}
    for file in module_files:

        file = module_dir / file
        name = f"{file.stem}"

        if (
            file.is_file()
            and file.suffix.lower() == ".py"
            and file.stem not in ["base", "__init__"]
        ):

            modules = importlib.import_module(f"bbot.modules.{name}", "bbot")

            for m in modules.__dict__.keys():
                module = getattr(modules, m)
                try:
                    if BaseModule in module.__bases__:
                        module._name = name
                        available_modules[name] = module
                        break
                except AttributeError:
                    continue
    return available_modules
