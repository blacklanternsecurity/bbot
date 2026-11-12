import subprocess
from pathlib import Path
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("bbot")
except PackageNotFoundError:
    __version__ = "0.0.0"


def _git_commit():
    # only git checkouts have .git next to the package (a file, not a dir, in worktrees)
    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "describe", "--always", "--dirty", "--abbrev=9", "--exclude=*"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


_commit = _git_commit()
__full_version__ = f"{__version__} (git:{_commit})" if _commit else __version__
