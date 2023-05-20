from pathlib import Path

from bbot.modules import module_loader

parent_dir = Path(__file__).parent

module_test_files = list(parent_dir.glob("test_module_*.py"))
module_test_files = [m.name.split("test_module_")[-1].split(".")[0] for m in module_test_files]

for module_name in module_loader.preloaded():
    module_name = module_name.lower()
    assert module_name in module_test_files, f'No test file found for module "{module_name}"'
