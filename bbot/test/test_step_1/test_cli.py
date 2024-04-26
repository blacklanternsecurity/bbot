from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_cli_scan(monkeypatch):
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
    result = await cli._main()
    assert result == True

    scan_home = scans_home / "test_cli_scan"
    assert (scan_home / "preset.yml").is_file(), "preset.yml not found"
    assert (scan_home / "wordcloud.tsv").is_file(), "wordcloud.tsv not found"
    assert (scan_home / "output.txt").is_file(), "output.txt not found"
    assert (scan_home / "output.csv").is_file(), "output.csv not found"
    assert (scan_home / "output.json").is_file(), "output.json not found"

    with open(scan_home / "preset.yml") as f:
        text = f.read()
        assert "  dns_resolution: false" in text

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


@pytest.mark.asyncio
async def test_cli_args(monkeypatch, caplog, capsys, clean_default_config):
    from bbot import cli

    caplog.set_level(logging.INFO)

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert len(out.splitlines()) == 1
    assert out.count(".") > 1

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "--list-modules"])
    result = await cli._main()
    assert result == None
    out, err = capsys.readouterr()
    # internal modules
    assert "| excavate" in out
    # output modules
    assert "| csv" in out
    # scan modules
    assert "| wayback" in out

    # output dir and scan name
    output_dir = bbot_test_dir / "bbot_cli_args_output"
    scan_name = "bbot_cli_args_scan_name"
    scan_dir = output_dir / scan_name
    assert not output_dir.exists()
    monkeypatch.setattr("sys.argv", ["bbot", "-o", str(output_dir), "-n", scan_name, "-y"])
    result = await cli._main()
    assert result == True
    assert output_dir.is_dir()
    assert scan_dir.is_dir()
    assert "[SCAN]" in open(scan_dir / "output.txt").read()
    assert "[INFO]" in open(scan_dir / "scan.log").read()

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--list-module-options"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| modules.wayback.urls" in out
    assert "| bool" in out
    assert "| emit URLs in addition to DNS_NAMEs" in out
    assert "| False" in out
    assert "| modules.massdns.wordlist" in out
    assert "| modules.robots.include_allow" in out

    # list module options by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "--list-module-options"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| modules.wayback.urls" in out
    assert "| bool" in out
    assert "| emit URLs in addition to DNS_NAMEs" in out
    assert "| False" in out
    assert "| modules.massdns.wordlist" in out
    assert not "| modules.robots.include_allow" in out

    # list module options by module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdns", "-lmo"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert out.count("modules.") == out.count("modules.massdns.")
    assert not "| modules.wayback.urls" in out
    assert "| modules.massdns.wordlist" in out
    assert not "| modules.robots.include_allow" in out

    # list output module options by module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "stdout", "-lmo"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert out.count("modules.") == out.count("modules.stdout.")

    # list flags
    monkeypatch.setattr("sys.argv", ["bbot", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| safe" in out
    assert "| Non-intrusive, safe to run" in out
    assert "| active" in out
    assert "| passive" in out

    # list only a single flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert not "| safe" in out
    assert "| active" in out
    assert not "| passive" in out

    # list multiple flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "safe", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| safe" in out
    assert "| active" in out
    assert not "| passive" in out

    # no args
    monkeypatch.setattr("sys.argv", ["bbot"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "Target:\n  -t TARGET [TARGET ...]" in out

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| massdns" in out
    assert "| httpx" in out
    assert "| robots" in out

    # list modules by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| massdns" in out
    assert "| httpx" in out
    assert not "| robots" in out

    # list modules by flag + required flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-rf", "passive", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| massdns" in out
    assert not "| httpx" in out

    # list modules by flag + excluded flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-ef", "active", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert "| massdns" in out
    assert not "| httpx" in out

    # list modules by flag + excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-em", "massdns", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == None
    assert not "| massdns" in out
    assert "| httpx" in out

    # output modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "csv,json", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 2/2 output modules, (csv,json)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "csv,json", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 3/3 output modules, (python,stdout,txt)" in caplog.text

    # output modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "subdomains", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 6/6 output modules, (csv,json,python,stdout,subdomains,txt)" in caplog.text

    # internal modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 5/5 internal modules (aggregate,cloud,dns,excavate,speculate)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "excavate", "speculate", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 3/3 internal modules (aggregate,cloud,dns)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "speculate=false", "-y"])
    result = await cli._main()
    assert result == True
    assert "Loaded 4/4 internal modules (aggregate,cloud,dns,excavate)" in caplog.text

    # custom target type
    out, err = capsys.readouterr()
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "ORG:evilcorp", "-y"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result == True
    assert "[ORG_STUB]          	evilcorp	TARGET" in out

    # activate modules by flag
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "passive"])
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

    # enable and exclude the same module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "ffuf_shortnames", "-em", "ffuf_shortnames"])
    result = await cli._main()
    assert result == None
    assert 'Unable to add scan module "ffuf_shortnames" because the module has been excluded' in caplog.text

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
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei"])
    result = await cli._main()
    assert result == False, "-m nuclei ran without --allow-deadly"
    assert "Please specify --allow-deadly to continue" in caplog.text

    # --allow-deadly
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei", "--allow-deadly"])
    result = await cli._main()
    assert result == True, "-m nuclei failed to run with --allow-deadly"

    # install all deps
    # monkeypatch.setattr("sys.argv", ["bbot", "--install-all-deps"])
    # success = await cli._main()
    # assert success, "--install-all-deps failed for at least one module"


def test_cli_config_validation(monkeypatch, caplog):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module option
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    cli.main()
    assert 'Could not find module option "modules.ipnegibhor.num_bits"' in caplog.text
    assert 'Did you mean "modules.ipneighbor.num_bits"?' in caplog.text

    # incorrect global option
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "web_spier_distance=4"])
    cli.main()
    assert 'Could not find module option "web_spier_distance"' in caplog.text
    assert 'Did you mean "web_spider_distance"?' in caplog.text


def test_cli_module_validation(monkeypatch, caplog):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdnss"])
    cli.main()
    assert 'Could not find scan module "massdnss"' in caplog.text
    assert 'Did you mean "massdns"?' in caplog.text

    # incorrect excluded module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "massdnss"])
    cli.main()
    assert 'Could not find module "massdnss"' in caplog.text
    assert 'Did you mean "massdns"?' in caplog.text

    # incorrect output module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "neoo4j"])
    cli.main()
    assert 'Could not find output module "neoo4j"' in caplog.text
    assert 'Did you mean "neo4j"?' in caplog.text

    # output module setup failed
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "websocket", "-c", "modules.websocket.url=", "-y"])
    cli.main()
    lines = caplog.text.splitlines()
    assert "Loaded 6/6 output modules, (csv,json,python,stdout,txt,websocket)" in caplog.text
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("WARNING  bbot.scanner:scanner.py")
            and l.endswith("Setup hard-failed for websocket: Must set URL")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("WARNING  bbot.modules.output.websocket:base.py") and l.endswith("Setting error state")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("ERROR    bbot.cli:cli.py")
            and l.endswith("Setup hard-failed for 1 modules (websocket) (--force to run module anyway)")
        ]
    )

    # only output module setup failed
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr(
        "sys.argv",
        ["bbot", "-om", "websocket", "-em", "python,stdout,csv,json,txt", "-c", "modules.websocket.url=", "-y"],
    )
    cli.main()
    lines = caplog.text.splitlines()
    assert "Loaded 1/1 output modules, (websocket)" in caplog.text
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("WARNING  bbot.scanner:scanner.py")
            and l.endswith("Setup hard-failed for websocket: Must set URL")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("WARNING  bbot.modules.output.websocket:base.py") and l.endswith("Setting error state")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("ERROR    bbot.cli:cli.py") and l.endswith("Failed to load output modules. Aborting.")
        ]
    )

    # incorrect flag
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomainenum"])
    cli.main()
    assert 'Could not find flag "subdomainenum"' in caplog.text
    assert 'Did you mean "subdomain-enum"?' in caplog.text

    # incorrect excluded flag
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-ef", "subdomainenum"])
    cli.main()
    assert 'Could not find flag "subdomainenum"' in caplog.text
    assert 'Did you mean "subdomain-enum"?' in caplog.text

    # incorrect required flag
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-rf", "subdomainenum"])
    cli.main()
    assert 'Could not find flag "subdomainenum"' in caplog.text
    assert 'Did you mean "subdomain-enum"?' in caplog.text


def test_cli_presets(monkeypatch, capsys, caplog):
    import yaml
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # show current preset
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "http_proxy=currentpresettest", "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    assert "  http_proxy: currentpresettest" in captured.out

    # show current preset (full)
    monkeypatch.setattr("sys.argv", ["bbot", "-c" "modules.c99.api_key=asdf", "--current-preset-full"])
    cli.main()
    captured = capsys.readouterr()
    assert "      api_key: asdf" in captured.out

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

    # invalid preset
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-p", "asdfasdfasdf", "-y"])
    cli.main()
    assert "file does not exist. Use -lp to list available presets" in caplog.text
