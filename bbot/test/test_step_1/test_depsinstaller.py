from importlib.metadata import version as installed_version

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_depsinstaller(monkeypatch, bbot_scanner):
    scan = bbot_scanner(
        "127.0.0.1",
    )
    await scan._prep()

    # test shell
    test_file = Path("/tmp/test_file")
    test_file.unlink(missing_ok=True)
    scan.helpers.depsinstaller.shell(module="plumbus", commands=[f"touch {test_file}"])
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    # test tasks
    scan.helpers.depsinstaller.tasks(
        module="plumbus",
        tasks=[{"name": "test task execution", "ansible.builtin.shell": {"cmd": f"touch {test_file}"}}],
    )
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    await scan._cleanup()


@pytest.mark.asyncio
async def test_depsinstaller_pip_deps_satisfied(bbot_scanner):
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    installer = scan.helpers.depsinstaller

    # pydantic is a core dependency, so it's always installed
    pydantic_version = installed_version("pydantic")
    assert installer._pip_deps_satisfied([]) == (True, "")
    assert installer._pip_deps_satisfied(["pydantic"]) == (True, "")
    assert installer._pip_deps_satisfied([f"pydantic=={pydantic_version}", "pydantic>=1.0"]) == (True, "")

    # not installed
    satisfied, reason = installer._pip_deps_satisfied(["bbot-nonexistent-package"])
    assert satisfied is False
    assert "is not installed" in reason

    # installed, but not at a version that satisfies the requirement
    satisfied, reason = installer._pip_deps_satisfied(["pydantic==0.0.1"])
    assert satisfied is False
    assert "does not satisfy" in reason

    # a single unsatisfied dep is enough to fail the whole set
    assert installer._pip_deps_satisfied(["pydantic", "bbot-nonexistent-package"])[0] is False

    # requirements that don't apply to this interpreter are skipped
    assert installer._pip_deps_satisfied(['bbot-nonexistent-package; python_version < "3.0"']) == (True, "")

    # requirements we can't parse are assumed satisfied
    assert installer._pip_deps_satisfied(["git+https://github.com/blacklanternsecurity/bbot.git"]) == (True, "")

    await scan._cleanup()


@pytest.mark.asyncio
async def test_depsinstaller_pip_constraints(monkeypatch, bbot_scanner):
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    installer = scan.helpers.depsinstaller

    commands = []

    class MockProcess:
        stdout = "Successfully installed nothing"

    async def mock_run(command, *args, **kwargs):
        commands.append(command)
        return MockProcess()

    monkeypatch.setattr(installer.parent_helper, "run", mock_run)

    def last_constraints():
        command = commands[-1]
        return Path(command[command.index("--constraint") + 1]).read_text()

    # custom constraints are passed through to pip
    assert await installer.pip_install(["pydantic"], constraints=["pydantic==1.2.3"]) is True
    assert "pydantic==1.2.3" in last_constraints()

    # modules without custom constraints fall back to bbot's own constraints
    for no_constraints in ([], None):
        assert await installer.pip_install(["pydantic"], constraints=no_constraints) is True
        bbot_constraints = last_constraints()
        assert "pydantic==1.2.3" not in bbot_constraints
        assert "pydantic" in bbot_constraints

    await scan._cleanup()


@pytest.mark.asyncio
async def test_depsinstaller_stale_pip_cache(monkeypatch, bbot_scanner):
    """
    A cached dependency success must not be trusted when its pip packages have since vanished
    from the environment, e.g. because the virtualenv was rebuilt by `uv sync`.
    """
    scan = bbot_scanner("127.0.0.1")
    await scan._prep()
    installer = scan.helpers.depsinstaller

    pip_installs = []

    async def mock_pip_install(packages, constraints=None):
        pip_installs.append(list(packages))
        return True

    async def mock_install_core_deps():
        return

    monkeypatch.setattr(installer, "pip_install", mock_pip_install)
    monkeypatch.setattr(installer, "install_core_deps", mock_install_core_deps)
    # keep our fake modules out of the shared setup status cache
    monkeypatch.setattr(installer, "setup_status_cache", scan.helpers.temp_filename())
    monkeypatch.setattr(installer, "setup_status", {})

    missing_module = "deps_test_missing"
    present_module = "deps_test_present"
    preloaded = scan.preset.module_loader._preloaded
    for module_name, pip_dep in ((missing_module, "bbot-nonexistent-package"), (present_module, "pydantic")):
        preloaded[module_name] = {
            "sudo": False,
            "deps": {
                "apt": [],
                "shell": [],
                "pip": [pip_dep],
                "pip_constraints": [],
                "common": [],
                "ansible": [],
            },
        }

    try:
        # first run: nothing is cached yet, so both modules install their deps
        succeeded, failed = await installer.install(missing_module, present_module)
        assert not failed
        assert succeeded == sorted([missing_module, present_module])
        assert sorted(pip_installs) == [["bbot-nonexistent-package"], ["pydantic"]]

        # second run: the cache is warm, but only pydantic is actually installed.
        # the missing package must be reinstalled instead of silently assumed present
        pip_installs.clear()
        succeeded, failed = await installer.install(missing_module, present_module)
        assert not failed
        assert succeeded == sorted([missing_module, present_module])
        assert pip_installs == [["bbot-nonexistent-package"]]
    finally:
        for module_name in (missing_module, present_module):
            preloaded.pop(module_name, None)
        await scan._cleanup()
