import logging
from pathlib import Path

from bbot.errors import *

log = logging.getLogger("bbot.presets.path")

DEFAULT_PRESET_PATH = Path(__file__).parent.parent.parent / "presets"


class PresetPath:
    """
    Keeps track of where to look for preset .yaml files
    """

    def __init__(self):
        self.paths = [DEFAULT_PRESET_PATH]

    def find(self, filename):
        filename_path = Path(filename).resolve()
        extension = filename_path.suffix.lower()
        file_candidates = set()
        extension_candidates = {".yaml", ".yml"}
        if extension:
            extension_candidates.add(extension.lower())
        else:
            file_candidates.add(filename_path.stem)
        for ext in extension_candidates:
            file_candidates.add(f"{filename_path.stem}{ext}")
        file_candidates = sorted(file_candidates)
        file_candidates_str = ",".join([str(s) for s in file_candidates])
        paths_to_search = self.paths
        if "/" in str(filename):
            if filename_path.parent not in paths_to_search:
                paths_to_search.append(filename_path.parent)
        log.debug(
            f"Searching for preset in {[str(p) for p in paths_to_search]}, file candidates: {file_candidates_str}"
        )
        for path in paths_to_search:
            for candidate in file_candidates:
                for file in path.rglob(candidate):
                    if file.is_file():
                        log.verbose(f'Found preset matching "{filename}" at {file}')
                        self.add_path(file.parent)
                        return file.resolve()
        raise ValidationError(
            f'Could not find preset at "{filename}" - file does not exist. Use -lp to list available presets'
        )

    def __str__(self):
        return ":".join([str(s) for s in self.paths])

    def add_path(self, path):
        path = Path(path).resolve()
        if path in self.paths:
            return
        if any(path.is_relative_to(p) for p in self.paths):
            return
        if not path.is_dir():
            log.debug(f'Path "{path.resolve()}" is not a directory')
            return
        self.paths.append(path)

    def __iter__(self):
        yield from self.paths


PRESET_PATH = PresetPath()
