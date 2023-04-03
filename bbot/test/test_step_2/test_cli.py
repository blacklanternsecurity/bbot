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

    old_sys_argv = sys.argv
    old_cli_options = args.cli_options

    # incorrect module option
    monkeypatch.setattr("sys.argv", ["bbot", "-c", "modules.ipnegibhor.num_bits=4"])
    monkeypatch.setattr(args, "cli_options", args.dummy_parser.parse_args())

    args.get_config()
    captured = capsys.readouterr()

    assert 'Could not find module option "modules.ipnegibhor.num_bits"' in captured.err
    assert 'Did you mean "modules.ipneighbor.num_bits"?' in captured.err

    # unpatch sys.argv
    monkeypatch.setattr("sys.argv", old_sys_argv)
    # unpatch cli_options
    monkeypatch.setattr(args, "cli_options", old_cli_options)
