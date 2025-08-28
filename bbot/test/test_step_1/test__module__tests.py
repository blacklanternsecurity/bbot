import logging
import importlib
from pathlib import Path

from bbot import Preset
from ..test_step_2.module_tests.base import ModuleTestBase

log = logging.getLogger("bbot.test.modules")

module_tests_dir = Path(__file__).parent.parent / "test_step_2" / "module_tests"

_module_test_files = list(module_tests_dir.glob("test_module_*.py"))
_module_test_files.sort(key=lambda p: p.name)
module_test_files = [m.name.split("test_module_")[-1].split(".")[0] for m in _module_test_files]


def test__module__tests():
    preset = Preset()

    # make sure each module has a .py file
    for module_name, preloaded in preset.module_loader.preloaded().items():
        module_name = module_name.lower()
        assert module_name in module_test_files, f'No test file found for module "{module_name}"'

    # make sure each test file has a test class
    for file in _module_test_files:
        module_name = file.stem
        import_path = f"bbot.test.test_step_2.module_tests.{module_name}"
        module_test_variables = importlib.import_module(import_path, "bbot")
        module_pass = False
        for var_name in dir(module_test_variables):
            if var_name.startswith("Test"):
                test_class = getattr(module_test_variables, var_name)
                if ModuleTestBase in getattr(test_class, "__mro__", ()):
                    module_pass = True
                    break
        assert module_pass, f"Couldn't find a test class for {module_name} in {file}"
