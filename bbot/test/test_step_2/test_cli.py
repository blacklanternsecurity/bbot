from ..bbot_fixtures import *


def test_cli(monkeypatch, bbot_config):
    from bbot import cli

    monkeypatch.setattr(sys, "exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(os, "_exit", lambda *args, **kwargs: True)
    monkeypatch.setattr(cli, "config", bbot_config)

    old_sys_argv = sys.argv

    # show version
    monkeypatch.setattr("sys.argv", ["bbot", "--version"])
    cli.main()

    # show current config
    monkeypatch.setattr("sys.argv", ["bbot", "-y", "--current-config"])
    cli.main()

    # list modules
    monkeypatch.setattr("sys.argv", ["bbot", "-l"])
    cli.main()

    # list module options
    monkeypatch.setattr("sys.argv", ["bbot", "--help-all"])
    cli.main()

    # basic scan
    home_dir = Path(bbot_config["home"])
    monkeypatch.setattr(
        sys,
        "argv",
        ["bbot", "-y", "-t", "www.example.com", "-om", "human", "csv", "json", "-n", "test_scan"],
    )
    cli.main()

    # unpatch sys.argv
    monkeypatch.setattr("sys.argv", old_sys_argv)

    scan_home = home_dir / "scans" / "test_scan"
    assert (scan_home / "wordcloud.tsv").is_file()
    assert (scan_home / "output.txt").is_file()
    assert (scan_home / "output.csv").is_file()
    assert (scan_home / "output.json").is_file()
    with open(scan_home / "output.csv") as f:
        lines = f.readlines()
        assert lines[0] == "Event type,Event data,IP Address,Source Module,Scope Distance,Event Tags\n"
        assert len(lines) > 1


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
