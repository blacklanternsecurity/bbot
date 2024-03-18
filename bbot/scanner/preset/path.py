import logging
from pathlib import Path

from bbot.core.errors import PresetNotFoundError

log = logging.getLogger("bbot.presets.path")

DEFAULT_PRESET_PATH = Path(__file__).parent.parent.parent / "presets"


class PresetPath:
    """
    Keeps track of where to look for preset .yaml files
    """

    def __init__(self):
        self.paths = [DEFAULT_PRESET_PATH]
        self.add_path(Path.cwd())

    def find(self, filename):
        filename = Path(filename)
        self.add_path(filename.parent)
        self.add_path(filename.parent / "presets")
        if filename.is_file():
            log.hugesuccess(filename)
            return filename
        extension = filename.suffix.lower()
        file_candidates = set()
        for ext in (".yaml", ".yml"):
            if extension != ext:
                file_candidates.add(f"{filename.stem}{ext}")
        file_candidates = sorted(file_candidates)
        log.debug(f"Searching for preset in {self.paths}, file candidates: {file_candidates}")
        for path in self.paths:
            for candidate in file_candidates:
                for file in path.rglob(candidate):
                    log.verbose(f'Found preset matching "{filename}" at {file}')
                    return file
        raise PresetNotFoundError(f'Could not find preset at "{filename}" - file does not exist')

    def add_path(self, path):
        path = Path(path)
        if path in self.paths:
            return
        if not path.is_dir():
            log.debug(f'Path "{path}" is not a directory')
            return
        self.paths.append(path)


PRESET_PATH = PresetPath()
