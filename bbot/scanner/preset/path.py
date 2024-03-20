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
        filename = Path(filename).resolve()
        self.add_path(filename.parent)
        if filename.is_file():
            log.hugesuccess(filename)
            return filename
        extension = filename.suffix.lower()
        file_candidates = set()
        if not extension:
            file_candidates.add(filename.stem)
        for ext in (".yaml", ".yml"):
            if extension != ext:
                file_candidates.add(f"{filename.stem}{ext}")
        file_candidates = sorted(file_candidates)
        file_candidates_str = ",".join([str(s) for s in file_candidates])
        log.debug(f"Searching for preset in {self}, file candidates: {file_candidates_str}")
        for path in self.paths:
            for candidate in file_candidates:
                for file in path.rglob(candidate):
                    log.verbose(f'Found preset matching "{filename}" at {file}')
                    return file.resolve()
        raise PresetNotFoundError(f'Could not find preset at "{filename}" - file does not exist')

    def __str__(self):
        return ":".join([str(s) for s in self.paths])

    def add_path(self, path):
        path = Path(path).resolve()
        if path in self.paths:
            return
        if not path.is_dir():
            log.debug(f'Path "{path.resolve()}" is not a directory')
            return
        self.paths.append(path)


PRESET_PATH = PresetPath()
