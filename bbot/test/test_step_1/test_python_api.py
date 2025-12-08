from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_python_api():
    from bbot import Scanner

    # make sure events are properly yielded
    scan1 = Scanner("127.0.0.1")
    events1 = []
    async for event in scan1.async_start():
        events1.append(event)
    assert any("127.0.0.1" == e for e in events1)
    # make sure output files work
    scan2 = Scanner("127.0.0.1", output_modules=["json"], scan_name="python_api_test")
    await scan2.async_start_without_generator()
    scan_home = scan2.helpers.scans_dir / "python_api_test"
    out_file = scan_home / "output.json"
    assert list(scan2.helpers.read_file(out_file))
    scan_log = scan_home / "scan.log"
    debug_log = scan_home / "debug.log"
    assert scan_log.is_file()
    assert "python_api_test" in open(scan_log).read()
    assert debug_log.is_file()
    assert "python_api_test" in open(debug_log).read()

    scan3 = Scanner("127.0.0.1", output_modules=["json"], scan_name="scan_logging_test")
    await scan3.async_start_without_generator()

    assert "scan_logging_test" not in open(scan_log).read()
    assert "scan_logging_test" not in open(debug_log).read()

    scan_home = scan3.helpers.scans_dir / "scan_logging_test"
    out_file = scan_home / "output.json"
    assert list(scan3.helpers.read_file(out_file))
    scan_log = scan_home / "scan.log"
    debug_log = scan_home / "debug.log"
    assert scan_log.is_file()
    assert debug_log.is_file()
    assert "scan_logging_test" in open(scan_log).read()
    assert "scan_logging_test" in open(debug_log).read()

    # make sure config loads properly
    bbot_home = "/tmp/.bbot_python_api_test"
    Scanner("127.0.0.1", config={"home": bbot_home})
    assert os.environ["BBOT_TOOLS"] == str(Path(bbot_home) / "tools")

    # output modules override
    scan4 = Scanner()
    assert set(scan4.preset.output_modules) == {"csv", "json", "python", "txt"}
    scan5 = Scanner(output_modules=["json"])
    assert set(scan5.preset.output_modules) == {"json"}

    # custom target types
    custom_target_scan = Scanner("ORG:evilcorp")
    events = [e async for e in custom_target_scan.async_start()]
    assert 1 == len([e for e in events if e.type == "ORG_STUB" and e.data == "evilcorp" and "target" in e.tags])

    # presets
    scan6 = Scanner("evilcorp.com", presets=["subdomain-enum"])
    assert "sslcert" in scan6.preset.modules


def test_python_api_sync():
    from bbot.scanner import Scanner

    # make sure events are properly yielded
    scan1 = Scanner("127.0.0.1")
    events1 = []
    for event in scan1.start():
        events1.append(event)
    assert any("127.0.0.1" == e for e in events1)
    # make sure output files work
    scan2 = Scanner("127.0.0.1", output_modules=["json"], scan_name="python_api_test")
    scan2.start_without_generator()
    out_file = scan2.helpers.scans_dir / "python_api_test" / "output.json"
    assert list(scan2.helpers.read_file(out_file))
    # make sure config loads properly
    bbot_home = "/tmp/.bbot_python_api_test"
    Scanner("127.0.0.1", config={"home": bbot_home})
    assert os.environ["BBOT_TOOLS"] == str(Path(bbot_home) / "tools")


def test_python_api_validation():
    from bbot.scanner import Scanner, Preset

    # invalid target
    with pytest.raises(ValidationError) as error:
        Scanner("asdf:::asdf")
    assert str(error.value) == 'Unable to autodetect data type from "asdf:::asdf"'
    # invalid module
    with pytest.raises(ValidationError) as error:
        Scanner(modules=["asdf"])
    assert str(error.value) == 'Could not find scan module "asdf". Did you mean "asn"?'
    # invalid output module
    with pytest.raises(ValidationError) as error:
        Scanner(output_modules=["asdf"])
    assert str(error.value) == 'Could not find output module "asdf". Did you mean "teams"?'
    # invalid excluded module
    with pytest.raises(ValidationError) as error:
        Scanner(exclude_modules=["asdf"])
    assert str(error.value) == 'Could not find module "asdf". Did you mean "asn"?'
    # invalid flag
    with pytest.raises(ValidationError) as error:
        Scanner(flags=["asdf"])
    assert str(error.value) == 'Could not find flag "asdf". Did you mean "safe"?'
    # invalid required flag
    with pytest.raises(ValidationError) as error:
        Scanner(require_flags=["asdf"])
    assert str(error.value) == 'Could not find flag "asdf". Did you mean "safe"?'
    # invalid excluded flag
    with pytest.raises(ValidationError) as error:
        Scanner(exclude_flags=["asdf"])
    assert str(error.value) == 'Could not find flag "asdf". Did you mean "safe"?'
    # output module as normal module
    with pytest.raises(ValidationError) as error:
        Scanner(modules=["json"])
    assert str(error.value) == 'Could not find scan module "json". Did you mean "asn"?'
    # normal module as output module
    with pytest.raises(ValidationError) as error:
        Scanner(output_modules=["robots"])
    assert str(error.value) == 'Could not find output module "robots". Did you mean "web_report"?'
    # invalid preset type
    with pytest.raises(ValidationError) as error:
        Scanner(preset="asdf")
    assert str(error.value) == 'Preset must be of type Preset, not "str"'
    # include nonexistent preset
    with pytest.raises(ValidationError) as error:
        Preset(include=["nonexistent"])
    assert (
        str(error.value)
        == 'Could not find preset at "nonexistent" - file does not exist. Use -lp to list available presets'
    )
