from pathlib import Path


_SAFE_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\tfsmonitor = false
\tsymlinks = false
\tsshCommand = echo
[transfer]
\tfsckObjects = true
"""


def sanitize_git_repo(repo_folder: Path):
    # replace the git config with a safe one that neutralizes dangerous directives
    # the original is preserved in the repo folder so secret-scanning tools can still inspect it
    config_file = repo_folder / ".git" / "config"
    if config_file.exists():
        config_file.rename(repo_folder / "git_config_original")
    config_file.write_text(_SAFE_GIT_CONFIG)
    # leave .git/index in place -- it's binary metadata (filename-to-SHA mappings),
    # not a security risk, and removing it breaks tools that need to clone the repo
    # move the hooks folder
    hooks_folder = repo_folder / ".git" / "hooks"
    if hooks_folder.exists():
        hooks_folder.rename(repo_folder / "git_hooks_original")
