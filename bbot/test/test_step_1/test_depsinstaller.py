from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_depsinstaller(monkeypatch, bbot_scanner):
    scan = bbot_scanner(
        "127.0.0.1",
    )

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
