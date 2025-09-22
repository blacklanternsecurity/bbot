from pathlib import Path


def sanitize_git_repo(repo_folder: Path):
    # sanitizing the git config is infeasible since there are too many different ways to do evil things
    # instead, we move it out of .git and into the repo folder, so we don't miss any secrets etc. inside
    config_file = repo_folder / ".git" / "config"
    if config_file.exists():
        config_file.rename(repo_folder / "git_config_original")
    # move the index file
    index_file = repo_folder / ".git" / "index"
    if index_file.exists():
        index_file.rename(repo_folder / "git_index_original")
    # move the hooks folder
    hooks_folder = repo_folder / ".git" / "hooks"
    if hooks_folder.exists():
        hooks_folder.rename(repo_folder / "git_hooks_original")
