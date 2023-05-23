from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_cli(monkeypatch, bbot_config):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli, "config", bbot_config)

    old_sys_argv = sys.argv

    home_dir = Path(bbot_config["home"])
    scans_home = home_dir / "scans"

    # basic scan
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bbot",
            "-y",
            "-t",
            "127.0.0.1",
            "www.example.com",
            "-om",
            "human",
            "csv",
            "json",
            "-n",
            "test_cli_scan",
            "-c",
            "dns_resolution=False",
            "-o",
            "/tmp",
        ],
    )
    await cli._main()

    scan_home = scans_home / "test_cli_scan"
    assert (scan_home / "wordcloud.tsv").is_file()
    assert (scan_home / "output.txt").is_file()
    assert (scan_home / "output.csv").is_file()
    assert (scan_home / "output.json").is_file()
    with open(scan_home / "output.csv") as f:
        lines = f.readlines()
        assert lines[0] == "Event type,Event data,IP Address,Source Module,Scope Distance,Event Tags\n"
        assert len(lines) > 1

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
    assert ip_success and dns_success

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    await cli._main()

    # start agent
    monkeypatch.setattr("sys.argv", ["bbot", "--agent-mode"])
    task = asyncio.create_task(cli._main())
    await asyncio.sleep(2)
    task.cancel()
    await task

    # no args
    monkeypatch.setattr("sys.argv", ["bbot"])
    await cli._main()

    # enable module by flag
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "report"])
    await cli._main()

    # unconsoleable output module
    monkeypatch.setattr("sys.argv", ["bbot", "-om", "web_report"])
    await cli._main()

    # install all deps
    monkeypatch.setattr("sys.argv", ["bbot", "--install-all-deps"])
    success = await cli._main()
    assert success, "--install-all-deps failed for at least one module"

    # unresolved dependency
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "wappalyzer"])
    await cli._main()

    # resolved dependency, excluded module
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "ffuf_shortnames", "-em", "ffuf_shortnames"])
    await cli._main()

    # require flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-rf", "passive"])
    await cli._main()

    # excluded flags
    monkeypatch.setattr("sys.argv", ["bbot", "-f", "active", "-ef", "active"])
    await cli._main()

    # slow modules
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "massdns"])
    await cli._main()

    # deadly modules
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei"])
    result = await cli._main()
    assert result == False

    # --allow-deadly
    monkeypatch.setattr("sys.argv", ["bbot", "-m", "nuclei", "--allow-deadly"])
    result = await cli._main()
    assert result != False

    # show current config
    monkeypatch.setattr("sys.argv", ["bbot", "-y", "--current-config"])
    await cli._main()

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "-l"])
    await cli._main()

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--help-all"])
    await cli._main()

    # unpatch sys.argv
    monkeypatch.setattr("sys.argv", old_sys_argv)


def test_config_validation(monkeypatch, capsys, bbot_config):
    from bbot import cli
    from bbot.core.configurator import args

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli, "config", bbot_config)

    old_cli_config = args.cli_config

    # incorrect module option
    monkeypatch.setattr(args, "cli_config", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module option "modules.ipnegibhor.num_bits"' in captured.err
    assert 'Did you mean "modules.ipneighbor.num_bits"?' in captured.err

    # incorrect global option
    monkeypatch.setattr(args, "cli_config", ["bbot", "-c", "web_spier_distance=4"])
    cli.main()
    captured = capsys.readouterr()
    assert 'Could not find module option "web_spier_distance"' in captured.err
    assert 'Did you mean "web_spider_distance"?' in captured.err

    # unpatch cli_options
    monkeypatch.setattr(args, "cli_config", old_cli_config)


def test_module_validation(monkeypatch, capsys, bbot_config):
    from bbot.core.configurator import args

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)

    old_sys_argv = sys.argv

    # incorrect module
    monkeypatch.setattr(sys, "argv", ["bbot", "-m", "massdnss"])
    args.parser.parse_args()
    captured = capsys.readouterr()
    assert 'Could not find module "massdnss"' in captured.err
    assert 'Did you mean "massdns"?' in captured.err

    # incorrect excluded module
    monkeypatch.setattr(sys, "argv", ["bbot", "-em", "massdnss"])
    args.parser.parse_args()
    captured = capsys.readouterr()
    assert 'Could not find module "massdnss"' in captured.err
    assert 'Did you mean "massdns"?' in captured.err

    # incorrect output module
    monkeypatch.setattr(sys, "argv", ["bbot", "-om", "neoo4j"])
    args.parser.parse_args()
    captured = capsys.readouterr()
    assert 'Could not find output module "neoo4j"' in captured.err
    assert 'Did you mean "neo4j"?' in captured.err

    # incorrect flag
    monkeypatch.setattr(sys, "argv", ["bbot", "-f", "subdomainenum"])
    args.parser.parse_args()
    captured = capsys.readouterr()
    assert 'Could not find flag "subdomainenum"' in captured.err
    assert 'Did you mean "subdomain-enum"?' in captured.err

    # unpatch sys.argv
    monkeypatch.setattr("sys.argv", old_sys_argv)
