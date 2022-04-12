from pathlib import Path
from ...core.helpers.misc import list_files


def module_filter(file):
    return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]


module_dir = Path(__file__).parent
module_files = list(list_files(module_dir, filter=module_filter))
module_stems = [file.stem for file in module_files]


def get_modules():

    import importlib
    from .base import BaseOutputModule

    available_modules = {}
    for file in module_files:
        name = f"{file.stem}"
        modules = importlib.import_module(f"bbot.modules.output.{name}", "bbot")

        for m in modules.__dict__.keys():
            module = getattr(modules, m)
            try:
                if BaseOutputModule in getattr(module, "__bases__", []):
                    module._name = name
                    available_modules[name] = module
                    break
            except AttributeError:
                continue
    return available_modules
