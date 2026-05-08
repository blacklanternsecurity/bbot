"""Regression test for the cwd-walking bug in ``gitdumper.regex_files``.

When the ``folder=`` arg defaulted to ``Path()``, calling
``regex_files(file=foo)`` silently scanned the entire current working
directory in addition to the requested file — decoding every file in
the cwd into a Python string and running regex over it. With many
``CODE_REPOSITORY`` events that allocated 100+ GB.
"""

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403


@pytest.mark.asyncio
async def test_regex_files_does_not_walk_cwd(bbot_scanner, tmp_path, monkeypatch):
    """``regex_files(file=foo)`` must scan only ``foo`` — not the cwd."""
    target = tmp_path / "head"
    target.write_text("ref: refs/heads/main\n")

    decoy_cwd = tmp_path / "cwd"
    decoy_cwd.mkdir()
    (decoy_cwd / "decoy.txt").write_text("ref: refs/heads/should_not_match\n")
    monkeypatch.chdir(decoy_cwd)

    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        gitdumper = scan.modules["gitdumper"]
        regex = gitdumper.helpers.re.compile(r"ref: refs/heads/([a-zA-Z\d_-]+)")
        results = await gitdumper.regex_files(regex, file=target)

        assert "main" in results, "expected the requested file to be scanned"
        assert "should_not_match" not in results, "regex_files walked the cwd in addition to the requested file"
    finally:
        await scan._cleanup()
