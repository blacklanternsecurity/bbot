import time
from ..bbot_fixtures import *
from subprocess import CalledProcessError


@pytest.mark.asyncio
async def test_command(bbot_scanner):
    scan1 = bbot_scanner()

    # test timeouts
    command = ["sleep", "3"]
    start = time.time()
    with pytest.raises(asyncio.exceptions.TimeoutError):
        await scan1.helpers.run(command, idle_timeout=1)
    end = time.time()
    elapsed = end - start
    assert 0 < elapsed < 2

    start = time.time()
    with pytest.raises(asyncio.exceptions.TimeoutError):
        async for line in scan1.helpers.run_live(command, idle_timeout=1):
            print(line)
    end = time.time()
    elapsed = end - start
    assert 0 < elapsed < 2

    # run
    assert "plumbus\n" == (await scan1.helpers.run(["echo", "plumbus"])).stdout
    assert b"plumbus\n" == (await scan1.helpers.run(["echo", "plumbus"], text=False)).stdout
    result = (await scan1.helpers.run(["cat"], input="some\nrandom\nstdin")).stdout
    assert result.splitlines() == ["some", "random", "stdin"]
    result = (await scan1.helpers.run(["cat"], input=b"some\nrandom\nstdin", text=False)).stdout
    assert result.splitlines() == [b"some", b"random", b"stdin"]
    result = (await scan1.helpers.run(["cat"], input=["some", "random", "stdin"])).stdout
    assert result.splitlines() == ["some", "random", "stdin"]
    result = (await scan1.helpers.run(["cat"], input=[b"some", b"random", b"stdin"], text=False)).stdout
    assert result.splitlines() == [b"some", b"random", b"stdin"]

    # test overflow - run
    tmpfile_path = Path("/tmp/test_bigfile")
    with open(tmpfile_path, "w") as f:
        # write 2MB
        f.write("A" * 1024 * 1024 * 2)
    result = (await scan1.helpers.run(["cat", str(tmpfile_path)], limit=1024 * 64, text=False)).stdout
    assert len(result) == 1024 * 1024 * 2
    tmpfile_path.unlink(missing_ok=True)
    # test overflow - run_live
    tmpfile_path = Path("/tmp/test_bigfile")
    with open(tmpfile_path, "w") as f:
        # write 2MB
        f.write("A" * 10 + "\n")
        f.write("B" * 1024 * 1024 * 2 + "\n")
        f.write("C" * 10 + "\n")
    lines = []
    async for line in scan1.helpers.run_live(["cat", str(tmpfile_path)], limit=1024 * 64):
        lines.append(line)
    # only a small bit of the overflowed line survives, that's okay.
    assert lines == ["AAAAAAAAAA", "BBBBBBBBBBB", "CCCCCCCCCC"]
    tmpfile_path.unlink(missing_ok=True)

    # run_live
    lines = []
    async for line in scan1.helpers.run_live(["echo", "plumbus"]):
        lines.append(line)
    assert lines == ["plumbus"]
    lines = []
    async for line in scan1.helpers.run_live(["echo", "plumbus"], text=False):
        lines.append(line)
    assert lines == [b"plumbus"]
    lines = []
    async for line in scan1.helpers.run_live(["cat"], input="some\nrandom\nstdin"):
        lines.append(line)
    assert lines == ["some", "random", "stdin"]
    lines = []
    async for line in scan1.helpers.run_live(["cat"], input=["some", "random", "stdin"]):
        lines.append(line)
    assert lines == ["some", "random", "stdin"]

    # test check=True
    with pytest.raises(CalledProcessError) as excinfo:
        lines = [line async for line in scan1.helpers.run_live(["ls", "/aslkdjflasdkfsd"], check=True)]
    assert "No such file or directory" in excinfo.value.stderr
    with pytest.raises(CalledProcessError) as excinfo:
        lines = [line async for line in scan1.helpers.run_live(["ls", "/aslkdjflasdkfsd"], check=True, text=False)]
    assert b"No such file or directory" in excinfo.value.stderr
    with pytest.raises(CalledProcessError) as excinfo:
        await scan1.helpers.run(["ls", "/aslkdjflasdkfsd"], check=True)
    assert "No such file or directory" in excinfo.value.stderr
    with pytest.raises(CalledProcessError) as excinfo:
        await scan1.helpers.run(["ls", "/aslkdjflasdkfsd"], check=True, text=False)
    assert b"No such file or directory" in excinfo.value.stderr

    # test piping
    lines = []
    async for line in scan1.helpers.run_live(
        ["cat"], input=scan1.helpers.run_live(["echo", "-en", r"some\nrandom\nstdin"])
    ):
        lines.append(line)
    assert lines == ["some", "random", "stdin"]
    lines = []
    async for line in scan1.helpers.run_live(
        ["cat"], input=scan1.helpers.run_live(["echo", "-en", r"some\nrandom\nstdin"], text=False), text=False
    ):
        lines.append(line)
    assert lines == [b"some", b"random", b"stdin"]

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
    await scan1.load_modules()
    path_parts = os.environ.get("PATH", "").split(":")
    assert "/tmp/.bbot_test/tools" in path_parts
    run_lines = (await scan1.helpers.run(["env"])).stdout.splitlines()
    assert "BBOT_WEB_USER_AGENT=BBOT Test User-Agent" in run_lines
    for line in run_lines:
        if line.startswith("PATH="):
            path_parts = line.split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_lines_sudo = (await scan1.helpers.run(["env"], sudo=True)).stdout.splitlines()
    assert "BBOT_WEB_USER_AGENT=BBOT Test User-Agent" in run_lines_sudo
    for line in run_lines_sudo:
        if line.startswith("PATH="):
            path_parts = line.split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_live_lines = [l async for l in scan1.helpers.run_live(["env"])]
    assert "BBOT_WEB_USER_AGENT=BBOT Test User-Agent" in run_live_lines
    for line in run_live_lines:
        if line.startswith("PATH="):
            path_parts = line.strip().split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts
    run_live_lines_sudo = [l async for l in scan1.helpers.run_live(["env"], sudo=True)]
    assert "BBOT_WEB_USER_AGENT=BBOT Test User-Agent" in run_live_lines_sudo
    for line in run_live_lines_sudo:
        if line.startswith("PATH="):
            path_parts = line.strip().split("=", 1)[-1].split(":")
            assert "/tmp/.bbot_test/tools" in path_parts

    await scan1._cleanup()
