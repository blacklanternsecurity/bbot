from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_command(bbot_scanner, bbot_config):
    scan1 = bbot_scanner(config=bbot_config)

    # run
    assert "plumbus\n" == (await scan1.helpers.run(["echo", "plumbus"])).stdout
    result = (await scan1.helpers.run(["cat"], input="some\nrandom\nstdin")).stdout
    assert result.splitlines() == ["some", "random", "stdin"]

    # run_live
    lines = []
    async for line in scan1.helpers.run_live(["echo", "plumbus"]):
        lines.append(line)
    assert lines == ["plumbus"]
    lines = []
    async for line in scan1.helpers.run_live(["cat"], input="some\nrandom\nstdin"):
        lines.append(line)
    assert lines == ["some", "random", "stdin"]

    # test piping
    lines = []
    async for line in scan1.helpers.run_live(
        ["cat"], input=scan1.helpers.run_live(["echo", "-en", r"some\nrandom\nstdin"])
    ):
        lines.append(line)
    assert lines == ["some", "random", "stdin"]

    # test missing executable
    result = await scan1.helpers.run(["sgkjlskdfsdf"])
    assert result is None
    lines = [l async for l in scan1.helpers.run_live(["ljhsdghsdf"])]
    assert not lines
    # test stderr
    result = await scan1.helpers.run(["ls", "/sldikgjasldkfsdf"])
    assert "No such file or directory" in result.stderr
    lines = [l async for l in scan1.helpers.run_live(["ls", "/sldikgjasldkfsdf"])]
    assert not lines

    # test sudo + existence of environment variables
    scan1.load_modules()
    path_parts = os.environ.get("PATH", "").split(":")
    assert "/tmp/.bbot_test/tools" in path_parts
    run_lines = (await scan1.helpers.run(["env"])).stdout.splitlines()
    assert f"BBOT_PLUMBUS=asdf" in run_lines
    for line in run_lines:
        if line.startswith("PATH="):
            path_parts = line.split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_lines_sudo = (await scan1.helpers.run(["env"], sudo=True)).stdout.splitlines()
    assert f"BBOT_PLUMBUS=asdf" in run_lines_sudo
    for line in run_lines_sudo:
        if line.startswith("PATH="):
            path_parts = line.split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_live_lines = [l async for l in scan1.helpers.run_live(["env"])]
    assert f"BBOT_PLUMBUS=asdf" in run_live_lines
    for line in run_live_lines:
        if line.startswith("PATH="):
            path_parts = line.strip().split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_live_lines_sudo = [l async for l in scan1.helpers.run_live(["env"], sudo=True)]
    assert f"BBOT_PLUMBUS=asdf" in run_live_lines_sudo
    for line in run_live_lines_sudo:
        if line.startswith("PATH="):
            path_parts = line.strip().split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
