from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_python_api(clean_default_config):
    from bbot.scanner import Scanner

    # make sure events are properly yielded
    scan1 = Scanner("127.0.0.1")
    await scan1._prep()
    events1 = []
    async for event in scan1.async_start():
        events1.append(event)
    assert any(e.type == "IP_ADDRESS" and e.data == "127.0.0.1" for e in events1)
    # make sure output files work
    scan2 = Scanner("127.0.0.1", output_modules=["json"], scan_name="python_api_test")
    await scan2._prep()
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
    await scan3._prep()
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
    scan4 = Scanner("127.0.0.1", config={"home": bbot_home})
    await scan4._prep()
    assert os.environ["BBOT_TOOLS"] == str(Path(bbot_home) / "tools")

    # output modules are additive
    scan5 = Scanner()
    assert set(scan5.preset.output_modules) == {"csv", "json", "txt"}
    # adding json is a no-op (already a default), defaults stay
    scan6 = Scanner(output_modules=["json"])
    assert set(scan6.preset.output_modules) == {"csv", "json", "txt"}
    # use exclude_output_modules to remove defaults
    scan6b = Scanner(exclude_output_modules=["csv", "txt"])
    assert set(scan6b.preset.output_modules) == {"json"}

    # custom target types
    custom_target_scan = Scanner("ORG:evilcorp")
    events = [e async for e in custom_target_scan.async_start()]

    assert 1 == len([e for e in events if e.type == "ORG_STUB" and e.data == "evilcorp" and "seed" in e.tags])

    # presets
    scan7 = Scanner("evilcorp.com", presets=["subdomain-enum"])
    assert "sslcert" in scan7.preset.modules


@pytest.mark.asyncio
async def test_python_api_sync(clean_default_config):
    from bbot.scanner import Scanner

    # make sure events are properly yielded
    scan1 = Scanner("127.0.0.1")
    await scan1._prep()
    events1 = []
    async for event in scan1.async_start():
        events1.append(event)
    assert any(e.type == "IP_ADDRESS" and e.data == "127.0.0.1" for e in events1)
    # make sure output files work
    scan2 = Scanner("127.0.0.1", output_modules=["json"], scan_name="python_api_test")
    await scan2._prep()
    await scan2.async_start_without_generator()
    out_file = scan2.helpers.scans_dir / "python_api_test" / "output.json"
    assert list(scan2.helpers.read_file(out_file))
    # make sure config loads properly
    bbot_home = "/tmp/.bbot_python_api_test"
    scan3 = Scanner("127.0.0.1", config={"home": bbot_home})
    await scan3._prep()
    assert os.environ["BBOT_TOOLS"] == str(Path(bbot_home) / "tools")


def test_python_api_sync_no_pending_tasks():
    """Test that no asyncio tasks remain pending after a sync scan completes.

    Regression test for https://github.com/blacklanternsecurity/bbot/issues/2508
    When using BBOT as a library (e.g. from Celery), orphaned asyncio tasks
    would cause "Task was destroyed but it is pending!" warnings on shutdown.
    """
    import asyncio
    from bbot.scanner import Scanner
    from bbot.core.helpers.async_helpers import get_event_loop

    scan = Scanner("127.0.0.1")
    events = list(scan.start())
    assert any(e.type == "IP_ADDRESS" and e.data == "127.0.0.1" for e in events)

    # After the sync generator is exhausted, no tasks should remain pending
    loop = get_event_loop()
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    assert len(pending) == 0, f"Found {len(pending)} pending tasks after scan: {pending}"


async def test_python_api_validation():
    from bbot.scanner import Scanner, Preset

    # invalid target
    with pytest.raises(ValidationError) as error:
        scan = Scanner("asdf:::asdf")
        await scan._prep()
    assert str(error.value) == 'Unable to autodetect data type from "asdf:::asdf"'
    # invalid module
    with pytest.raises(ValidationError) as error:
        scan = Scanner(modules=["asdf"])
        await scan._prep()
    assert str(error.value) == 'Could not find scan module "asdf". Did you mean "asn"?'
    # invalid output module
    with pytest.raises(ValidationError) as error:
        Scanner(output_modules=["asdf"])
    assert str(error.value) == 'Could not find output module "asdf". Did you mean "nats"?'
    # invalid excluded module
    with pytest.raises(ValidationError) as error:
        scan = Scanner(exclude_modules=["asdf"])
        await scan._prep()
    assert str(error.value) == 'Could not find module "asdf". Did you mean "asn"?'
    # invalid flag
    with pytest.raises(ValidationError) as error:
        Scanner(flags=["activ"])
    assert str(error.value) == 'Could not find flag "activ". Did you mean "active"?'
    # invalid required flag
    with pytest.raises(ValidationError) as error:
        Scanner(require_flags=["activ"])
    assert str(error.value) == 'Could not find flag "activ". Did you mean "active"?'
    # invalid excluded flag
    with pytest.raises(ValidationError) as error:
        Scanner(exclude_flags=["activ"])
    assert str(error.value) == 'Could not find flag "activ". Did you mean "active"?'
    # output module as normal module
    with pytest.raises(ValidationError) as error:
        scan = Scanner(modules=["json"])
        await scan._prep()
    assert str(error.value) == 'Could not find scan module "json". Did you mean "asn"?'
    # normal module as output module
    with pytest.raises(ValidationError) as error:
        Scanner(output_modules=["robots"])
    assert str(error.value) == 'Could not find output module "robots". Did you mean "rabbitmq"?'
    # invalid preset type
    with pytest.raises(ValidationError) as error:
        scan = Scanner(preset="asdf")
        await scan._prep()
    assert str(error.value) == 'Preset must be of type Preset, not "str"'
    # include nonexistent preset
    with pytest.raises(ValidationError) as error:
        Preset(include=["nonexistent"])
    assert (
        str(error.value)
        == 'Could not find preset at "nonexistent" - file does not exist. Use -lp to list available presets'
    )
