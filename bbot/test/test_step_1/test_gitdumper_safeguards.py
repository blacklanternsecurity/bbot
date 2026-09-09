"""Regression tests for ``gitdumper`` safeguards against pathological / malicious
git layouts.

Each test demonstrates a failure mode that would either leak memory, hang, or
recurse without bound on the unfixed code.
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


@pytest.mark.asyncio
async def test_download_files_caps_max_size(bbot_scanner, tmp_path, monkeypatch):
    """``download_files`` must pass an explicit ``max_size`` to ``helpers.download``.

    Without it, a misconfigured / malicious server can return up to 500 MB
    (the web helper default) per probed git path. Real git refs/info files
    are tiny, so capping at a few MB shuts down a whole class of abuse.
    """
    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        gitdumper = scan.modules["gitdumper"]
        seen_kwargs = []

        async def traced_download(url, **kwargs):
            seen_kwargs.append(kwargs)
            return None

        monkeypatch.setattr(gitdumper.helpers, "download", traced_download)

        url = gitdumper.helpers.urlparse("http://example.com/.git/HEAD")
        await gitdumper.download_files([url], tmp_path)

        assert seen_kwargs, "expected helpers.download to be called"
        for call in seen_kwargs:
            assert "max_size" in call, "max_size must be passed to helpers.download"
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_download_object_caps_recursion_depth(bbot_scanner, tmp_path, monkeypatch):
    """``download_object`` must bound recursion depth.

    Mocks ``git_catfile`` so every object's output yields a fresh new hash,
    creating an infinite chain. With no cap we'd recurse until Python's
    stack limit (or the OS kills us). With a cap we stop at a finite depth.
    """
    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        gitdumper = scan.modules["gitdumper"]

        async def nop_download_files(urls, folder):
            return True

        monkeypatch.setattr(gitdumper, "download_files", nop_download_files)

        counter = [0]

        async def fake_catfile(hash_, option="-t", folder=None):
            counter[0] += 1
            new_hash = f"{counter[0]:040x}"
            return f"object content with {new_hash}"

        monkeypatch.setattr(gitdumper, "git_catfile", fake_catfile)

        await gitdumper.download_object("0" * 40, "http://example.com", tmp_path)

        # If recursion is bounded, counter stays well below Python's stack limit.
        # We just need to confirm it didn't spiral out — anything < 500 means
        # the cap is in effect.
        assert counter[0] < 500, f"download_object recursed {counter[0]} levels — cap not in effect"
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_download_object_detects_cycles(bbot_scanner, tmp_path, monkeypatch):
    """``download_object`` must not re-process an object hash it has
    already visited. Malicious or corrupt git repos can have cyclic
    references."""
    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        gitdumper = scan.modules["gitdumper"]

        async def nop_download_files(urls, folder):
            return True

        monkeypatch.setattr(gitdumper, "download_files", nop_download_files)

        hash_a = "a" * 40
        hash_b = "b" * 40
        catfile_calls = []

        async def fake_catfile(hash_, option="-t", folder=None):
            catfile_calls.append(hash_)
            if hash_ == hash_a:
                return f"references {hash_b}"
            if hash_ == hash_b:
                return f"references {hash_a}"  # cycle back
            return ""

        monkeypatch.setattr(gitdumper, "git_catfile", fake_catfile)

        await gitdumper.download_object(hash_a, "http://example.com", tmp_path)

        # With cycle detection: A -> B -> stop (A already seen). 2 catfile calls.
        # Without: infinite, eventually RecursionError.
        assert len(catfile_calls) <= 2, (
            f"download_object did not detect cycle (called catfile {len(catfile_calls)} times)"
        )
    finally:
        await scan._cleanup()
