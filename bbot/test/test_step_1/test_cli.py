import stat
import yaml

from ..bbot_fixtures import *

from bbot import cli


@pytest.mark.asyncio
async def test_cli_scope(monkeypatch, capsys):
    import json

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # basic target (seeds and target are the same)
    monkeypatch.setattr(
        "sys.argv",
        ["bbot", "-t", "one.one.one.one", "-c", "scope.report_distance=10", "dns.minimal=false", "--json", "-y"],
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
            if l["module"] == "SEED" and l["scope_distance"] == 0 and "in-scope" in l["tags"] and "seed" in l["tags"]
        ]
    )
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.1.1.1"]
    assert ip_events
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in ip_events)
    ip_events = [l for l in lines if l["type"] == "IP_ADDRESS" and l["data"] == "1.0.0.1"]
    assert ip_events
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in ip_events)

    # with target_list different from seeds (seeds are one.one.one.one, target is 192.168.0.1)
    monkeypatch.setattr(
        "sys.argv",
        [
            "bbot",
            "-t",
            "192.168.0.1",
            "-s",
            "one.one.one.one",
            "-c",
            "scope.report_distance=10",
            "dns.minimal=false",
            "dns.search_distance=2",
            "--json",
            "-y",
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
    # When seeds are different from target, the seed DNS_NAME should be out-of-scope
    # (distance-1) and tagged as a seed, but NOT tagged as a target (since it is not
    # part of the target set that in_target() checks).
    assert all(l["scope_distance"] == 1 and "distance-1" in l["tags"] for l in dns_events)
    target_seed_events = [
        l
        for l in dns_events
        if l["module"] == "SEED" and l["scope_distance"] == 1 and "distance-1" in l["tags"] and "seed" in l["tags"]
    ]
    assert len(target_seed_events) == 1
    assert all("target" not in l["tags"] for l in target_seed_events)
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
            if "[IP_ADDRESS]        \t127.0.0.1\tSEED" in line:
                ip_success = True
            if "[DNS_NAME]          \twww.example.com\tSEED" in line:
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
    # description and scan_name should reflect the CLI name
    assert preset["description"] == "depstest"
    assert preset["scan_name"] == "depstest"
    # deps behavior should be set to retry_failed, but allow other config keys to exist
    assert preset.get("config", {}).get("deps") == {"behavior": "retry_failed"}

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
    assert "| loud " in out
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
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "loud", "--list-flags"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| loud " in out
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
    assert "| http " in out
    assert "| robots " in out

    # list modules by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| dnsbrute " in out
    assert "| http " in out
    assert "| robots " not in out

    # list modules by flag + required flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-rf", "passive", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| chaos " in out
    assert "| http " not in out

    # list modules by flag + excluded flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-ef", "active", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| chaos " in out
    assert "| http " not in out

    # list modules by flag + excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "subdomain-enum", "-em", "dnsbrute", "-l"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is None
    assert "| dnsbrute " not in out
    assert "| http " in out

    # -om is additive (defaults stay)
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "csv,json", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 4/4 output modules, (csv,json,stdout,txt)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "csv,json", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 2/2 output modules, (stdout,txt)" in caplog.text

    # -om adds non-default module on top of defaults
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "subdomains", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 5/5 output modules, (csv,json,stdout,subdomains,txt)" in caplog.text

    # -eom removes output modules
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-eom", "csv,txt", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 2/2 output modules, (json,stdout)" in caplog.text

    # internal modules (python is now internal)
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-y"])
    result = await cli._main()
    assert result is True
    assert (
        "Loaded 7/7 internal modules (aggregate,cloudcheck,dnsresolve,excavate,python,speculate,unarchive)"
        in caplog.text
    )
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-em", "excavate", "speculate", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,python,unarchive)" in caplog.text
    caplog.clear()
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "speculate=false", "-y"])
    result = await cli._main()
    assert result is True
    assert "Loaded 6/6 internal modules (aggregate,cloudcheck,dnsresolve,excavate,python,unarchive)" in caplog.text

    # custom target type
    out, err = capsys.readouterr()
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "ORG:evilcorp", "-y"])
    result = await cli._main()
    out, err = capsys.readouterr()
    assert result is True
    assert "[ORG_STUB]          	evilcorp\tSEED" in out

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

    # python dependency
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "baddns"])
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

    # invasive modules should run without a gate (just warnings)
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "dotnetnuke"])
    result = await cli._main()
    assert result is True, "-m dotnetnuke should run without any special flags"

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

    # a module with options must list them (regression: help_text reads the pydantic
    # Config, not the removed self.options dict — otherwise every module shows nothing)
    monkeypatch.setattr("sys.argv", ["bbot", "--module-help", "robots"])
    assert await cli._main() is None
    captured = capsys.readouterr()
    assert "include_sitemap" in captured.out
    assert "No options available" not in captured.out

    # lightfuzz overrides help_text as a classmethod (regression: it must not read
    # instance-only config, which previously crashed with AttributeError)
    monkeypatch.setattr("sys.argv", ["bbot", "--module-help", "lightfuzz"])
    assert await cli._main() is None
    captured = capsys.readouterr()
    assert "Lightfuzz Submodules:" in captured.out
    assert "sqli" in captured.out
    assert "enabled_submodules" in captured.out


def test_cli_config_validation(monkeypatch, caplog):
    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    # incorrect module name nested under modules.* — surfaces as an unknown
    # module with a closest-match suggestion (more useful than the legacy
    # "Could not find config option ..." phrasing)
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    cli.main()
    assert 'Could not find module "ipnegibhor"' in caplog.text
    assert 'Did you mean "ipneighbor"?' in caplog.text

    # incorrect global option
    caplog.clear()
    assert not caplog.text
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "web_spier_distance=4"])
    cli.main()
    assert 'Could not find config option "web_spier_distance"' in caplog.text
    assert 'Did you mean "web.spider_distance"?' in caplog.text


def test_parse_cli_value_keeps_date_shaped_strings():
    """`-c key=2024-01-01` must stay a string -- YAML would coerce it to a date object,
    which every typed field rejects (e.g. an all-numeric or date-shaped credential).
    Normal type coercion for typed options is preserved."""
    from bbot.scanner.preset.args import _parse_cli_value

    assert _parse_cli_value("2024-01-01") == "2024-01-01"
    assert _parse_cli_value("2") == 2
    assert _parse_cli_value("true") is True
    assert _parse_cli_value("3.5") == 3.5
    assert _parse_cli_value("[a, b]") == ["a", "b"]
    assert _parse_cli_value("") == ""
    assert _parse_cli_value("hello") == "hello"


def test_parse_dotted_cli_type_aware_string_fields():
    """String fields keep the literal CLI text (lossless) so an all-numeric or
    boolean-looking value isn't coerced to int/bool and rejected by the str type."""
    from bbot.scanner.preset.args import parse_dotted_cli
    from bbot.scanner import validate_preset
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    index = MODULE_LOADER.config_type_index
    for raw, expect in [("12345678", "12345678"), ("true", "true"), ("0755", "0755")]:
        d = parse_dotted_cli([f"modules.postgres.password={raw}"], index=index)
        assert d["modules"]["postgres"]["password"] == expect
        assert validate_preset({"config": d}) == []


def test_parse_dotted_cli_type_aware_preserves_scalars():
    """Typed options still coerce (int/bool), and Union[str, list[str]] still parses a
    list while keeping a bare value as a string."""
    from bbot.scanner.preset.args import parse_dotted_cli
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    index = MODULE_LOADER.config_type_index
    assert parse_dotted_cli(["web.http_timeout=20"], index=index)["web"]["http_timeout"] == 20
    assert parse_dotted_cli(["scope.strict=true"], index=index)["scope"]["strict"] is True
    wl = parse_dotted_cli(["modules.dnsbrute.wordlist=[a,b]"], index=index)["modules"]["dnsbrute"]["wordlist"]
    assert wl == ["a", "b"]
    bare = parse_dotted_cli(["modules.dnsbrute.wordlist=foo"], index=index)["modules"]["dnsbrute"]["wordlist"]
    assert bare == "foo"


def test_parse_dotted_cli_type_aware_bool_fields():
    """Bool fields produce real bool values, not ints or strings."""
    from bbot.scanner.preset.args import parse_dotted_cli
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    index = MODULE_LOADER.config_type_index
    d = parse_dotted_cli(["modules.lightfuzz.force_common_headers=1"], index=index)
    assert d["modules"]["lightfuzz"]["force_common_headers"] is True
    d = parse_dotted_cli(["scope.strict=yes"], index=index)
    assert d["scope"]["strict"] is True
    d = parse_dotted_cli(["scope.strict=false"], index=index)
    assert d["scope"]["strict"] is False


def test_type_aware_parsing_still_flags_unknown_key():
    """Type-awareness must not hide a typo: an unknown key falls back to YAML parse
    and is still rejected by validation."""
    from bbot.scanner.preset.args import parse_dotted_cli
    from bbot.scanner import validate_preset
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    d = parse_dotted_cli(["web.bogus=5"], index=MODULE_LOADER.config_type_index)
    assert validate_preset({"config": d})  # non-empty: unknown key flagged


def test_coerce_config_file_values():
    """coerce_config fixes YAML-parsed values from config files: numeric passwords
    become strings, integer 1 on a bool field becomes True, etc."""
    from bbot.core.config.models import coerce_config
    from bbot.core.modules import MODULE_LOADER

    MODULE_LOADER.preload()
    index = MODULE_LOADER.config_type_index
    cfg = {
        "web": {"http_timeout": 30},
        "modules": {
            "postgres": {"password": 12345678, "port": 5432},
            "lightfuzz": {"force_common_headers": 1},
        },
    }
    result = coerce_config(cfg, index)
    assert result["modules"]["postgres"]["password"] == "12345678"
    assert result["modules"]["postgres"]["port"] == 5432
    assert result["modules"]["lightfuzz"]["force_common_headers"] is True
    assert result["web"]["http_timeout"] == 30


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
    assert "Loaded 5/5 output modules, (csv,json,stdout,txt,websocket)" in caplog.text
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("ERROR    bbot.scanner:scanner.py")
            and l.endswith("Setup hard-failed for websocket: Must set URL")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("ERROR    bbot.modules.output.websocket:base.py") and l.endswith("Setting error state")
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
            if l.startswith("ERROR    bbot.scanner:scanner.py")
            and l.endswith("Setup hard-failed for websocket: Must set URL")
        ]
    )
    assert 1 == len(
        [
            l
            for l in lines
            if l.startswith("ERROR    bbot.modules.output.websocket:base.py") and l.endswith("Setting error state")
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


def test_cli_presets(monkeypatch, capsys, caplog, clean_default_config):
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


@pytest.mark.asyncio
async def test_cli_no_color(monkeypatch):
    from bbot.logger import colorize
    from bbot.scanner import Preset

    # colorize honors the NO_COLOR convention
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert colorize("test", "INFO") != "test"
    monkeypatch.setenv("NO_COLOR", "1")
    assert colorize("test", "INFO") == "test"

    # the --no-color CLI switch sets NO_COLOR (restored by monkeypatch at teardown)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "evilcorp.com", "--no-color"])
    preset = Preset()
    preset.parse_args()
    assert os.environ.get("NO_COLOR") == "1"


@pytest.mark.asyncio
async def test_cli_console_control_chars(monkeypatch, capsys):
    import logging
    from bbot.logger import log_to_stderr
    from bbot.core.config.logger import ColoredFormatter

    monkeypatch.delenv("NO_COLOR", raising=False)

    # scan-derived text carrying the bytes that flip a terminal into its line-drawing charset:
    # 0x0e (Shift Out) and an "ESC ( 0" designate-line-drawing sequence
    dirty = "matched banner: \x1b(0\x0edeadbeef"

    # the stderr log formatter escapes control chars before adding its own colors
    formatter = ColoredFormatter("%(levelname)s %(name)s: %(message)s")
    record = logging.LogRecord(
        name="bbot.modules.nuclei",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="%s",
        args=(dirty,),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "\x0e" not in formatted
    assert "\x1b(0" not in formatted
    assert "\\x0e" in formatted and "\\x1b(0" in formatted
    # BBOT's own ANSI color codes survive (escaping happens on the message, before colorizing)
    assert "\x1b[" in formatted

    # same protection on the early bootstrap path
    log_to_stderr(dirty, level="INFO")
    out, err = capsys.readouterr()
    assert "\x0e" not in err and "\x1b(0" not in err
    assert "\\x0e" in err

    # tracebacks and stack info are also sanitized (an exception carrying scan-derived
    # bytes must not reach the terminal unescaped via logger.exception / exc_info=True)
    try:
        raise ValueError(dirty)
    except ValueError:
        exc_record = logging.LogRecord(
            name="bbot.modules.nuclei",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=None,
            exc_info=sys.exc_info(),
        )
    formatted = formatter.format(exc_record)
    assert "\x0e" not in formatted and "\x1b(0" not in formatted
    assert "\\x0e" in formatted and "ValueError" in formatted

    stack_record = logging.LogRecord(
        name="bbot.modules.nuclei",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="boom",
        args=None,
        exc_info=None,
    )
    stack_record.stack_info = f"Stack: {dirty}"
    formatted = formatter.format(stack_record)
    assert "\x0e" not in formatted and "\x1b(0" not in formatted
    assert "\\x0e" in formatted


@pytest.mark.asyncio
async def test_cli_reset_config(monkeypatch, caplog, tmp_path):
    from bbot.core import CORE

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    caplog.set_level(logging.INFO)

    files = CORE.files_config
    monkeypatch.setattr(files, "config_dir", tmp_path)
    monkeypatch.setattr(files, "config_filename", tmp_path / "bbot.yml")
    monkeypatch.setattr(files, "secrets_filename", tmp_path / "secrets.yml")
    config_file = tmp_path / "bbot.yml"
    secrets_file = tmp_path / "secrets.yml"

    # a customized bbot.yml on disk
    config_file.write_text("scope:\n  strict: false\n")

    # without --yes and no TTY, it refuses and changes nothing
    monkeypatch.setattr("sys.argv", ["bbot", "--reset-config"])
    caplog.clear()
    await cli._main()
    assert "Refusing to reset config without confirmation" in caplog.text
    assert not (tmp_path / "bbot.yml.bak").exists()
    assert config_file.read_text() == "scope:\n  strict: false\n"

    # --reset-config -y regenerates bbot.yml and backs it up, but never touches secrets.yml
    monkeypatch.setattr("sys.argv", ["bbot", "--reset-config", "-y"])
    caplog.clear()
    await cli._main()
    assert "Regenerated config files" in caplog.text
    assert (tmp_path / "bbot.yml.bak").is_file()
    assert (tmp_path / "bbot.yml.bak").read_text() == "scope:\n  strict: false\n"
    assert "# NOTICE" in config_file.read_text()
    assert not (tmp_path / "secrets.yml.bak").exists()

    # --reset-secrets -y regenerates secrets.yml (owner-only) and backs it up
    monkeypatch.setattr("sys.argv", ["bbot", "--reset-secrets", "-y"])
    caplog.clear()
    await cli._main()
    assert (tmp_path / "secrets.yml.bak").is_file()
    assert stat.S_IMODE(secrets_file.stat().st_mode) & 0o077 == 0


@pytest.mark.asyncio
async def test_cli_reset_config_hint(monkeypatch, caplog, tmp_path):
    from bbot.core import CORE

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    caplog.set_level(logging.INFO)

    files = CORE.files_config
    monkeypatch.setattr(files, "config_dir", tmp_path)
    monkeypatch.setattr(files, "config_filename", tmp_path / "bbot.yml")
    monkeypatch.setattr(files, "secrets_filename", tmp_path / "secrets.yml")

    # a bbot.yml carrying an option that no longer exists (e.g. left over from
    # an older version of BBOT), loaded into the config
    (tmp_path / "bbot.yml").write_text("scope:\n  strct: false\n")
    monkeypatch.setattr(CORE, "_custom_config", {"scope": {"strct": False}})

    monkeypatch.setattr("sys.argv", ["bbot", "-t", "example.com"])
    caplog.clear()
    await cli._main()

    # validation fails on the bad option, and (because it lives in bbot.yml) we
    # point the user at --reset-config -- but not at --reset-secrets
    assert "scope.strct" in caplog.text
    assert "regenerating from current defaults with: bbot --reset-config" in caplog.text
    assert "--reset-secrets" not in caplog.text


@pytest.mark.asyncio
async def test_cli_reset_config_hint_skips_cli_typo(monkeypatch, caplog, tmp_path):
    from bbot.core import CORE

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    caplog.set_level(logging.INFO)

    files = CORE.files_config
    monkeypatch.setattr(files, "config_dir", tmp_path)
    monkeypatch.setattr(files, "config_filename", tmp_path / "bbot.yml")
    monkeypatch.setattr(files, "secrets_filename", tmp_path / "secrets.yml")

    # the bad option comes from the CLI, not from any config file on disk
    monkeypatch.setattr("sys.argv", ["bbot", "-t", "example.com", "-c", "scope.strct=false"])
    caplog.clear()
    await cli._main()

    # validation still fails, but there's nothing to reset -- so no hint
    assert "scope.strct" in caplog.text
    assert "regenerating from current defaults" not in caplog.text
