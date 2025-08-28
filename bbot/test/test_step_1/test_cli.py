import yaml

from ..bbot_fixtures import *

from bbot import cli


@pytest.mark.asyncio
async def test_cli_scope(monkeypatch, capsys):
    import json

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # basic target without whitelist
    monkeypatch.setattr(
        "sys.argv",
        ["bbot", "-t", "one.one.one.one", "-c", "scope.report_distance=10", "dns.minimal=false", "--json"],
    )
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is True
    lines = [json.loads(l) for l in out.splitlines()]
    dns_events = [l for l in lines if l["type"] == "DNS_NAME" and l["data"] == "one.one.one.one"]
    assert dns_events
    assert all(l["scope_distance"] == 0 and "in-scope" in l["tags"] for l in dns_events)
    assert 1 == len(
        [
            l
            for l in dns_events
            if l["module"] == "TARGET"
            and l["scope_distance"] == 0
            and "in-scope" in l["tags"]
            and "target" in l["tags"]
        ]
    )
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.1.1.1"]
    assert ip_events
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in ip_events)
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.0.0.1"]
    assert ip_events
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in ip_events)

    # with whitelist
    monkeypatch.setattr(
        "sys.argv",
        [
            "bbot",
            "-t",
            "one.one.one.one",
            "-w",
            "192.168.0.1",
            "-c",
            "scope.report_distance=10",
            "dns.minimal=false",
            "dns.search_distance=2",
            "--json",
        ],
    )
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is True
    lines = [json.loads(l) for l in out.splitlines()]
    lines = [l for l in lines if l["type"] != "SCAN"]
    assert lines
    assert not any(l["scope_distance"] == 0 for l in lines)
    dns_events = [l for l in lines if l["type"] == "DNS_NAME" and l["data"] == "one.one.one.one"]
    assert dns_events
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in dns_events)
    assert 1 == len(
        [
            l
            for l in dns_events
            if l["module"] == "TARGET"
            and l["scope_distance"] == 1
            and "distance-1" in l["tags"]
            and "target" in l["tags"]
        ]
    )
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.1.1.1"]
    assert ip_events
    assert all(l["scope_distance"] == 2 and "distance-2" in l["tags"] for l in ip_events)
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.0.0.1"]
    assert ip_events
    assert all(l["scope_distance"] == 2 and "distance-2" in l["tags"] for l in ip_events)


@pytest.mark.asyncio
async def test_cli_scan(monkeypatch):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    scans_home = bbot_test_dir / "scans"

    # basic scan
    monkeypatch.setattr(
        sys,
        "argv",
        ["bbot", "-y", "-t", "127.0.0.1", "www.example.com", "-n", "test_cli_scan", "-c", "dns.disable=true"],
    )
    result = await cli._main()
    assert result is True

    scan_home = scans_home / "test_cli_scan"
    assert (scan_home / "preset.yml").is_file(), "preset.yml not found"
    assert (scan_home / "wordcloud.tsv").is_file(), "wordcloud.tsv not found"
    assert (scan_home / "output.txt").is_file(), "output.txt not found"
    assert (scan_home / "output.csv").is_file(), "output.csv not found"
    assert (scan_home / "output.json").is_file(), "output.json not found"

    with open(scan_home / "preset.yml") as f:
        text = f.read()
        assert "  dns:\n    disable: true" in text

    with open(scan_home / "output.csv") as f:
        lines = f.readlines()
        assert lines[0] == "Event type,Event data,IP Address,Source Module,Scope Distance,Event Tags,Discovery Path\n"
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

    # Check for gzipped scan log file
    scan_log = scan_home / "scan.log"
    assert scan_log.is_file(), "scan.log not found"
    assert "[INFO]" in open(scan_log).read()


@pytest.mark.asyncio
async def test_cli_args(monkeypatch, caplog, capsys, clean_default_config):
    caplog.set_level(logging.INFO)

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert len(out.splitlines()) == 1
    assert out.count(".") > 1

    # deps behavior
    monkeypatch.setattr("sys.argv", ["bbot", "-n", "depstest", "--retry-deps", "--current-preset"])
    result = await cli._main()
    assert result is None
    out, err = capsys.readouterr()
    print(out)
    # parse YAML output
    preset = yaml.safe_load(out)
    assert preset == {
        "description": "depstest",
        "scan_name": "depstest",
        "config": {"deps": {"behavior": "retry_failed"}},
    }

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "--list-modules"])
    result = await cli._main()
    assert result is None
    out, err = capsys.readouterr()
    # internal modules
    assert "| excavate " in out
    # no output modules
    assert not "| csv " in out
    # scan modules
    assert "| wayback " in out

    # list output modules
    monkeypatch.setattr("sys.argv", ["bbot", "--list-output-modules"])
    result = await cli._main()
    assert result == None
    out, err = capsys.readouterr()
    # no internal modules
    assert not "| excavate " in out
    # output modules
    assert "| csv " in out
    # no scan modules
    assert not "| wayback " in out

    # output dir and scan name
    output_dir = bbot_test_dir / "bbot_cli_args_output"
    scan_name = "bbot_cli_args_scan_name"
    scan_dir = output_dir / scan_name
    if output_dir.exists():
        shutil.rmtree(output_dir)
    monkeypatch.setattr("sys.argv", ["bbot", "-o", str(output_dir), "-n", scan_name, "-y"])
    result = await cli._main()
    assert result is True
    assert output_dir.is_dir()
    assert scan_dir.is_dir()
    assert "[SCAN]" in open(scan_dir / "output.txt").read()

    # Check for gzipped scan log file
    scan_log = scan_dir / "scan.log"
    assert scan_log.is_file(), "scan.log not found"
    assert "[INFO]" in open(scan_log).read()
    shutil.rmtree(output_dir)

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--list-module-options"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| modules.wayback.urls" in out
    assert "| bool" in out
    assert "| emit URLs in addition to DNS_NAMEs" in out
    assert "| False" in out
    assert "| modules.dnsbrute.wordlist" in out
    assert "| modules.robots.include_allow" in out

    # list module options by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "--list-module-options"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| modules.wayback.urls" in out
    assert "| bool" in out
    assert "| emit URLs in addition to DNS_NAMEs" in out
    assert "| False" in out
    assert "| modules.dnsbrute.wordlist" in out
    assert "| modules.robots.include_allow" not in out

    # list module options by module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "dnsbrute", "-lmo"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert out.count("modules.") == out.count("modules.dnsbrute.")
    assert "| modules.wayback.urls" not in out
    assert "| modules.dnsbrute.wordlist" in out
    assert "| modules.robots.include_allow" not in out

    # list output module options by module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "stdout", "-lmo"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert out.count("modules.") == out.count("modules.stdout.")

    # list flags
    monkeypatch.setattr("sys.argv", ["bbot", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| safe " in out
    assert "| Non-intrusive, safe to run " in out
    assert "| active " in out
    assert "| passive " in out

    # list only a single flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| safe " not in out
    assert "| active " in out
    assert "| passive " not in out

    # list multiple flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "safe", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| safe " in out
    assert "| active " in out
    assert "| passive " not in out

    # no args
    monkeypatch.setattr("sys.argv", ["bbot"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "-t TARGET [TARGET ...]" in out

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| dnsbrute " in out
    assert "| httpx " in out
    assert "| robots " in out

    # list modules by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| dnsbrute " in out
    assert "| httpx " in out
    assert "| robots " not in out

    # list modules by flag + required flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-rf", "passive", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| chaos " in out
    assert "| httpx " not in out

    # list modules by flag + excluded flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-ef", "active", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| chaos " in out
    assert "| httpx " not in out

    # list modules by flag + excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-em", "dnsbrute", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| dnsbrute " not in out
    assert "| httpx " in out

    # output modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "csv,json", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 2/2 output modules, (csv,json)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "csv,json", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 3/3 output modules, (python,stdout,txt)" in caplog.text

    # output modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "subdomains", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 6/6 output modules, (csv,json,python,stdout,subdomains,txt)" in caplog.text

    # internal modules override
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 6/6 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate,unarchive)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "excavate", "speculate", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 4/4 internal modules (aggregate,cloudcheck,dnsresolve,unarchive)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "speculate=false", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,unarchive)" in caplog.text

    # custom target type
    out, err = capsys.readouterr()
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "ORG:evilcorp", "-y"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is True
    assert "[ORG_STUB]          	evilcorp	TARGET" in out

    # activate modules by flag
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "passive"])
    result = await cli._main()
    assert result is True

    # unconsoleable output module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "web_report"])
    result = await cli._main()
    assert result is True

    # unresolved dependency
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "wappalyzer"])
    result = await cli._main()
    assert result is True

    # require flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-rf", "passive"])
    result = await cli._main()
    assert result is True

    # excluded flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-ef", "active"])
    result = await cli._main()
    assert result is True

    # slow modules
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "bucket_digitalocean"])
    result = await cli._main()
    assert result is True

    # deadly modules
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei"])
    result = await cli._main()
    assert result is False, "-m nuclei ran without --allow-deadly"
    assert "Please specify --allow-deadly to continue" in caplog.text

    # --allow-deadly
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei", "--allow-deadly"])
    result = await cli._main()
    assert result is True, "-m nuclei failed to run with --allow-deadly"

    # install all deps
    monkeypatch.setattr("sys.argv", ["bbot", "--install-all-deps"])
    success = await cli._main()
    assert success is True, "--install-all-deps failed for at least one module"


@pytest.mark.asyncio
async def test_cli_customheaders(monkeypatch, caplog, capsys):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # test custom headers
    monkeypatch.setattr(
        "sys.argv", ["bbot", "--custom-headers", "foo=bar", "foo2=bar2", "foo3=bar=3", "--current-preset"]
    )
    success = await cli._main()
    assert success is None, "setting custom headers on command line failed"
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["web"]["http_headers"] == {"foo": "bar", "foo2": "bar2", "foo3": "bar=3"}

    # test custom headers invalid (no "=")
    monkeypatch.setattr("sys.argv", ["bbot", "--custom-headers", "justastring", "--current-preset"])
    result = await cli._main()
    assert result is None
    assert "Custom headers not formatted correctly (missing '=')" in caplog.text
    caplog.clear()

    # test custom headers invalid (missing key)
    monkeypatch.setattr("sys.argv", ["bbot", "--custom-headers", "=nokey", "--current-preset"])
    result = await cli._main()
    assert result is None
    assert "Custom headers not formatted correctly (missing header name or value)" in caplog.text
    caplog.clear()

    # test custom headers invalid (missing value)
    monkeypatch.setattr("sys.argv", ["bbot", "--custom-headers", "missingvalue=", "--current-preset"])
    result = await cli._main()
    assert result is None
    assert "Custom headers not formatted correctly (missing header name or value)" in caplog.text


@pytest.mark.asyncio
async def test_cli_module_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    monkeypatch.setattr("sys.argv", ["bbot", "--module-help", "excavate"])
    success = await cli._main()
    assert success is None, "module help failed to execute"
    captured = capsys.readouterr()

    assert "Extracts domains from CSP headers" in captured.out
    assert "Module Help:" in captured.out


def test_cli_config_validation(monkeypatch, caplog):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module option
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    cli.main()
    assert 'Could not find config option "modules.ipnegibhor.num_bits"' in caplog.text
    assert 'Did you mean "modules.ipneighbor.num_bits"?' in caplog.text

    # incorrect global option
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "web_spier_distance=4"])
    cli.main()
    assert 'Could not find config option "web_spier_distance"' in caplog.text
    assert 'Did you mean "web.spider_distance"?' in caplog.text


def test_cli_module_validation(monkeypatch, caplog):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "dnsbrutes"])
    cli.main()
    assert 'Could not find scan module "dnsbrutes"' in caplog.text
    assert 'Did you mean "dnsbrute"?' in caplog.text

    # incorrect excluded module
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "dnsbrutes"])
    cli.main()
    assert 'Could not find module "dnsbrutes"' in caplog.text
    assert 'Did you mean "dnsbrute"?' in caplog.text

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

    # bad target
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "asdf:::sdf"])
    cli.main()
    assert 'Unable to autodetect data type from "asdf:::sdf"' in caplog.text

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

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # show current preset
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "web.http_proxy=currentpresettest", "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    assert "    http_proxy: currentpresettest" in captured.out

    # show current preset (full)
    monkeypatch.setattr("sys.argv", ["bbot", "-cmodules.c99.api_key=asdf", "--current-preset-full"])
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
  web:
    http_proxy: http://proxy1
        """
        )

    preset2_file = preset_dir / "cli_preset2.yml"
    with open(preset2_file, "w") as f:
        f.write(
            """
config:
  web:
    http_proxy: http://proxy2
        """
        )

    # test reading single preset
    monkeypatch.setattr("sys.argv", ["bbot", "-p", str(preset1_file.resolve()), "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["web"]["http_proxy"] == "http://proxy1"

    # preset overrides preset
    monkeypatch.setattr(
        "sys.argv", ["bbot", "-p", str(preset2_file.resolve()), str(preset1_file.resolve()), "--current-preset"]
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["web"]["http_proxy"] == "http://proxy1"

    # override other way
    monkeypatch.setattr(
        "sys.argv", ["bbot", "-p", str(preset1_file.resolve()), str(preset2_file.resolve()), "--current-preset"]
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["web"]["http_proxy"] == "http://proxy2"

    # --fast-mode
    monkeypatch.setattr("sys.argv", ["bbot", "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert list(stdout_preset) == ["description"]

    monkeypatch.setattr("sys.argv", ["bbot", "--fast", "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    stdout_preset.pop("description")
    assert stdout_preset == {
        "config": {
            "scope": {"strict": True},
            "dns": {"minimal": True},
            "modules": {"speculate": {"essential_only": True}},
        },
        "exclude_modules": ["excavate"],
    }

    # --proxy
    monkeypatch.setattr("sys.argv", ["bbot", "--proxy", "http://127.0.0.1:8080", "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    stdout_preset.pop("description")
    assert stdout_preset == {"config": {"web": {"http_proxy": "http://127.0.0.1:8080"}}}

    # cli config overrides all presets
    monkeypatch.setattr(
        "sys.argv",
        [
            "bbot",
            "-p",
            str(preset1_file.resolve()),
            str(preset2_file.resolve()),
            "-c",
            "web.http_proxy=asdf",
            "--current-preset",
        ],
    )
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["config"]["web"]["http_proxy"] == "asdf"

    # invalid preset
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-p", "asdfasdfasdf", "-y"])
    cli.main()
    assert "file does not exist. Use -lp to list available presets" in caplog.text

    preset1_file.unlink()
    preset2_file.unlink()

    # test output dir preset
    output_dir_preset_file = bbot_test_dir / "output_dir_preset.yml"
    scan_name = "cli_output_dir_test"
    output_dir = bbot_test_dir / "cli_output_dir_preset"
    scan_dir = output_dir / scan_name
    output_file = scan_dir / "output.txt"

    with open(output_dir_preset_file, "w") as f:
        f.write(
            f"""
output_dir: {output_dir}
scan_name: {scan_name}
        """
        )

    assert not output_dir.exists()
    assert not scan_dir.exists()
    assert not output_file.exists()

    monkeypatch.setattr("sys.argv", ["bbot", "-p", str(output_dir_preset_file.resolve()), "--current-preset"])
    cli.main()
    captured = capsys.readouterr()
    stdout_preset = yaml.safe_load(captured.out)
    assert stdout_preset["output_dir"] == str(output_dir)
    assert stdout_preset["scan_name"] == scan_name

    shutil.rmtree(output_dir, ignore_errors=True)
    shutil.rmtree(scan_dir, ignore_errors=True)
    shutil.rmtree(output_file, ignore_errors=True)

    assert not output_dir.exists()
    assert not scan_dir.exists()
    assert not output_file.exists()

    monkeypatch.setattr("sys.argv", ["bbot", "-p", str(output_dir_preset_file.resolve())])
    cli.main()
    captured = capsys.readouterr()
    assert output_dir.is_dir()
    assert scan_dir.is_dir()
    assert output_file.is_file()

    shutil.rmtree(output_dir, ignore_errors=True)
    shutil.rmtree(scan_dir, ignore_errors=True)
    shutil.rmtree(output_file, ignore_errors=True)
    output_dir_preset_file.unlink()
