from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_cli_args(monkeypatch, bbot_config):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    home_dir = Path(bbot_config["home"])
    scans_home = home_dir / "scans"

    # basic scan
    monkeypatch.setattr(
        sys,
        "argv",
        ["bbot", "-y", "-t", "127.0.0.1", "www.example.com", "-n", "test_cli_scan", "-c", "dns_resolution=False"],
    )
    await cli._main()

    scan_home = scans_home / "test_cli_scan"
    assert (scan_home / "wordcloud.tsv").is_file(), "wordcloud.tsv not found"
    assert (scan_home / "output.txt").is_file(), "output.txt not found"
    assert (scan_home / "output.csv").is_file(), "output.csv not found"
    assert (scan_home / "output.ndjson").is_file(), "output.ndjson not found"
    with open(scan_home / "output.csv") as f:
        lines = f.readlines()
        assert lines[0] == "Event type,Event data,IP Address,Source Module,Scope Distance,Event Tags\n"
        assert len(lines) > 1, "output.csv is not long enough"

    ip_success = False
    dns_success = False
    output_filename = scan_home / "output.txt"
    with open(output_filename) as f:
        lines = f.read().splitlines()
        for line in lines:
            if "[IP_ADDRESS]        \t127.0.0.1\tTARGET" in line:
                ip_success = True
            if "[DNS_NAME]          \twww.example.com\tTARGET" in line:
                dns_success = True
    assert ip_success and dns_success, "IP_ADDRESS and/or DNS_NAME are not present in output.txt"

    # nonexistent module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "asdf"])
    with pytest.raises(EnableModuleError):
        result = await cli._main()

    # nonexistent output module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "asdf"])
    with pytest.raises(EnableModuleError):
        result = await cli._main()

    # nonexistent flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "asdf"])
    with pytest.raises(EnableFlagError):
        result = await cli._main()

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    result = await cli._main()
    assert result == None

    # show current preset
    monkeypatch.setattr("sys.argv", ["bbot", "--current-preset"])
    result = await cli._main()
    assert result == None

    # show current preset (full)
    monkeypatch.setattr("sys.argv", ["bbot", "--current-preset-full"])
    result = await cli._main()
    assert result == None

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "--list-modules"])
    result = await cli._main()
    assert result == None

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--list-module-options"])
    result = await cli._main()
    assert result == None

    # list flags
    monkeypatch.setattr("sys.argv", ["bbot", "--list-flags"])
    result = await cli._main()
    assert result == None

    # no args
    monkeypatch.setattr("sys.argv", ["bbot"])
    result = await cli._main()
    assert result == None

    # enable module by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "report"])
    result = await cli._main()
    assert result == True

    # unconsoleable output module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "web_report"])
    result = await cli._main()
    assert result == True

    # unresolved dependency
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "wappalyzer"])
    result = await cli._main()
    assert result == True

    # resolved dependency, excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "ffuf_shortnames", "-em", "ffuf_shortnames"])
    result = await cli._main()
    assert result == True

    # require flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-rf", "passive"])
    result = await cli._main()
    assert result == True

    # excluded flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-ef", "active"])
    result = await cli._main()
    assert result == True

    # slow modules
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "bucket_digitalocean"])
    result = await cli._main()
    assert result == True

    # deadly modules
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei"])
    result = await cli._main()
    assert result == False, "-m nuclei ran without --allow-deadly"

    # --allow-deadly
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei", "--allow-deadly"])
    # result = await cli._main()
    # assert result == True, "-m nuclei failed to run with --allow-deadly"

    # install all deps
    # monkeypatch.setattr("sys.argv", ["bbot", "--install-all-deps"])
    # success = await cli._main()
    # assert success, "--install-all-deps failed for at least one module"


def test_config_validation(monkeypatch, capsys, bbot_config):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module option
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module option "modules.ipnegibhor.num_bits"' in captured.err
    assert 'Did you mean "modules.ipneighbor.num_bits"?' in captured.err

    # incorrect global option
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "web_spier_distance=4"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module option "web_spier_distance"' in captured.err
    assert 'Did you mean "web_spider_distance"?' in captured.err


def test_module_validation(monkeypatch, capsys, bbot_config):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdnss"])
    with pytest.raises(EnableModuleError):
        cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module "massdnss"' in captured.err
    assert 'Did you mean "massdns"?' in captured.err

    # incorrect excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "massdnss"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module "massdnss"' in captured.err
    assert 'Did you mean "massdns"?' in captured.err

    # incorrect output module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "neoo4j"])
    with pytest.raises(EnableModuleError):
        cli.main()
    captured = capsys.readouterr()
    assert 'Could not find output module "neoo4j"' in captured.err
    assert 'Did you mean "neo4j"?' in captured.err

    # incorrect flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomainenum"])
    with pytest.raises(EnableFlagError):
        cli.main()
    captured = capsys.readouterr()
    assert 'Could not find flag "subdomainenum"' in captured.err
    assert 'Did you mean "subdomain-enum"?' in captured.err
