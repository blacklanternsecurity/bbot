import logging
from pathlib import Path

from bbot.errors import *

log = logging.getLogger("bbot.presets.path")

DEFAULT_PRESET_PATH = Path(__file__).parent.parent.parent / "presets"
DEFAULT_PRESET_PATH = DEFAULT_PRESET_PATH.expanduser().resolve()


class PresetPath:
    """
    Keeps track of where to look for preset .yaml files
    """

    def __init__(self):
        self.paths = [DEFAULT_PRESET_PATH]
        self._listable = {DEFAULT_PRESET_PATH}

    def find(self, filename):
        filename_path = Path(filename).expanduser()
        if "/" in str(filename):
            resolved = filename_path.resolve()
            if resolved.is_file():
                self.add_path(resolved.parent)
                return resolved
            self.add_path(filename_path.parent)
        extension = filename_path.suffix.lower()
        file_candidates = set()
        extension_candidates = {".yaml", ".yml"}
        if extension:
            extension_candidates.add(extension.lower())
        for ext in extension_candidates:
            file_candidates.add(f"{filename_path.stem}{ext}")
        file_candidates = sorted(file_candidates)
        file_candidates_str = ",".join([str(s) for s in file_candidates])
        log.debug(f"Searching for {file_candidates_str} in {[str(p) for p in self.paths]}")
        for path in self.paths:
            for candidate in file_candidates:
                for file in path.rglob(f"**/{candidate}"):
                    if file.is_file():
                        log.verbose(f'Found preset matching "{filename}" at {file}')
                        self.add_path(file.parent)
                        return file
        raise ValidationError(
            f'Could not find preset at "{filename}" - file does not exist. Use -lp to list available presets'
        )

    def __str__(self):
        return ":".join([str(s) for s in self.paths])

    def add_path(self, path, listable=False):
        path = Path(path).expanduser().resolve()
        # skip if already in paths
        if path in self.paths:
            if listable:
                self._listable.add(path)
            return
        # skip if path is a subdirectory of any path in paths
        if any(path.is_relative_to(p) for p in self.paths):
            if listable:
                self._listable.add(path)
            return
        # skip if path is not a directory
        if not path.is_dir():
            log.debug(f'Path "{path.resolve()}" is not a directory')
            return
        # preemptively remove any paths that are subdirectories of the new path,
        # but never remove the default preset path
        self.paths = [p for p in self.paths if p == DEFAULT_PRESET_PATH or not p.is_relative_to(path)]
        self.paths.insert(0, path)
        if listable:
            self._listable.add(path)

    @property
    def listable_paths(self):
        return [p for p in self.paths if p in self._listable]

    def find_file(self, filename):
        """Search known preset paths for a file of any type (e.g. target lists).

        For absolute paths, checks directly. For relative paths, searches each
        known preset path and its subdirectories (consistent with how ``find()``
        uses rglob for preset YAML files), then falls back to CWD.

        Returns the resolved Path if found, otherwise None.
        """
        filename_path = Path(filename).expanduser()
        if filename_path.is_absolute():
            resolved = filename_path.resolve()
            return resolved if resolved.is_file() else None
        for path in self.paths:
            for match in path.rglob(str(filename_path)):
                if match.is_file():
                    return match.resolve()
        # fall back to CWD
        candidate = filename_path.resolve()
        if candidate.is_file():
            return candidate
        return None

    def __iter__(self):
        yield from self.paths


PRESET_PATH = PresetPath()
