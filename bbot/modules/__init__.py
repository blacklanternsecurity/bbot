import re
from pathlib import Path
from bbot.core.helpers.modules import module_loader

dir_regex = re.compile(r"^[a-z][a-z0-9_]*$")

parent_dir = Path(__file__).parent.resolve()
module_dirs = set([parent_dir])
for e in parent_dir.iterdir():
    if e.is_dir() and dir_regex.match(e.name) and not e.name == "modules":
        module_dirs.add(e)

for d in module_dirs:
    module_loader.preload(d)
