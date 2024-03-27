from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_cli_args(monkeypatch, capsys):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    scans_home = bbot_test_dir / "scans"

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

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert captured.out.count(".") > 1

    # show current preset
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "http_proxy=currentpresettest", "--current-preset"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "  http_proxy: currentpresettest" in captured.out

    # show current preset (full)
    monkeypatch.setattr("sys.argv", ["bbot", "--current-preset-full"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "      api_key: ''" in captured.out

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "--list-modules"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    # internal modules
    assert "| excavate" in captured.out
    # output modules
    assert "| csv" in captured.out
    # scan modules
    assert "| wayback" in captured.out

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--list-module-options"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| modules.wayback.urls" in captured.out
    assert "| bool" in captured.out
    assert "| emit URLs in addition to DNS_NAMEs" in captured.out
    assert "| False" in captured.out
    assert "| modules.massdns.wordlist" in captured.out
    assert "| modules.robots.include_allow" in captured.out

    # list module options by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "--list-module-options"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| modules.wayback.urls" in captured.out
    assert "| bool" in captured.out
    assert "| emit URLs in addition to DNS_NAMEs" in captured.out
    assert "| False" in captured.out
    assert "| modules.massdns.wordlist" in captured.out
    assert not "| modules.robots.include_allow" in captured.out

    # list module options by module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdns", "-lmo"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert not "| modules.wayback.urls" in captured.out
    assert "| modules.massdns.wordlist" in captured.out
    assert not "| modules.robots.include_allow" in captured.out

    # list flags
    monkeypatch.setattr("sys.argv", ["bbot", "--list-flags"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| safe" in captured.out
    assert "| Non-intrusive, safe to run" in captured.out
    assert "| active" in captured.out
    assert "| passive" in captured.out

    # list only a single flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "--list-flags"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert not "| safe" in captured.out
    assert "| active" in captured.out
    assert not "| passive" in captured.out

    # list multiple flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "safe", "--list-flags"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| safe" in captured.out
    assert "| active" in captured.out
    assert not "| passive" in captured.out

    # no args
    monkeypatch.setattr("sys.argv", ["bbot"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "Target:\n  -t TARGET [TARGET ...]" in captured.out

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "-l"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| massdns" in captured.out
    assert "| httpx" in captured.out
    assert "| robots" in captured.out

    # list modules by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-l"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| massdns" in captured.out
    assert "| httpx" in captured.out
    assert not "| robots" in captured.out

    # list modules by flag + required flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-rf", "passive", "-l"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| massdns" in captured.out
    assert not "| httpx" in captured.out

    # list modules by flag + excluded flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-ef", "active", "-l"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert "| massdns" in captured.out
    assert not "| httpx" in captured.out

    # list modules by flag + excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-em", "massdns", "-l"])
    result = await cli._main()
    assert result == None
    captured = capsys.readouterr()
    assert not "| massdns" in captured.out
    assert "| httpx" in captured.out

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
    result = await cli._main()
    assert result == True, "-m nuclei failed to run with --allow-deadly"

    # install all deps
    # monkeypatch.setattr("sys.argv", ["bbot", "--install-all-deps"])
    # success = await cli._main()
    # assert success, "--install-all-deps failed for at least one module"


def test_cli_config_validation(monkeypatch, capsys):
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


def test_cli_module_validation(monkeypatch, capsys):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdnss"])
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
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find output module "neoo4j"' in captured.err
    assert 'Did you mean "neo4j"?' in captured.err

    # incorrect flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomainenum"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find flag "subdomainenum"' in captured.err
    assert 'Did you mean "subdomain-enum"?' in captured.err

    # incorrect excluded flag
    monkeypatch.setattr("sys.argv", ["bbot", "-ef", "subdomainenum"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find flag "subdomainenum"' in captured.err
    assert 'Did you mean "subdomain-enum"?' in captured.err

    # incorrect required flag
    monkeypatch.setattr("sys.argv", ["bbot", "-rf", "subdomainenum"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find flag "subdomainenum"' in captured.err
    assert 'Did you mean "subdomain-enum"?' in captured.err


def test_cli_presets(monkeypatch, capsys):
    import yaml
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    preset_dir = bbot_test_dir / "test_cli_presets"
    preset_dir.mkdir(exist_ok=True)

    preset1_file = preset_dir / "cli_preset1.conf"
    with open(preset1_file, "w") as f:
        f.write(
            """
config:
  http_proxy: http://proxy1
        """
        )

    preset2_file = preset_dir / "cli_preset2.yml"
    with open(preset2_file, "w") as f:
        f.write(
            """
config:
  http_proxy: http://proxy2
        """
        )

    # test reading single preset
    monkeypatch.setattr("sys.argv", ["bbot", "-p", str(preset1_file.resolve()), "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["http_proxy"] == "http://proxy1"

    # preset overrides preset
    monkeypatch.setattr(
        "sys.argv", ["bbot", "-p", str(preset2_file.resolve()), str(preset1_file.resolve()), "--current-preset"]
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["http_proxy"] == "http://proxy1"

    # override other way
    monkeypatch.setattr(
        "sys.argv", ["bbot", "-p", str(preset1_file.resolve()), str(preset2_file.resolve()), "--current-preset"]
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["http_proxy"] == "http://proxy2"

    # cli config overrides all presets
    monkeypatch.setattr(
        "sys.argv",
        [
            "bbot",
            "-p",
            str(preset1_file.resolve()),
            str(preset2_file.resolve()),
            "-c",
            "http_proxy=asdf",
            "--current-preset",
        ],
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["http_proxy"] == "asdf"
