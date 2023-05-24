import asyncio

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_files(bbot_scanner, bbot_config):
    scan1 = bbot_scanner(config=bbot_config)

    # tempfile
    tempfile = scan1.helpers.tempfile(("line1", "line2"), pipe=False)
    assert list(scan1.helpers.read_file(tempfile)) == ["line1", "line2"]
    tempfile = scan1.helpers.tempfile(("line1", "line2"), pipe=True)
    assert list(scan1.helpers.read_file(tempfile)) == ["line1", "line2"]

    # tempfile tail
    results = []
    tempfile = scan1.helpers.tempfile_tail(callback=lambda x: results.append(x))
    with open(tempfile, "w") as f:
        f.write("asdf\n")
    await asyncio.sleep(0.1)
    assert "asdf" in results
