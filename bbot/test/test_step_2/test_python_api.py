from ..bbot_fixtures import *


def test_python_api(bbot_config):
    from bbot.scanner import Scanner

    # make sure events are properly yielded
    scan1 = Scanner("127.0.0.1", config=bbot_config)
    events1 = list(scan1.start())
    assert any("127.0.0.1" == e for e in events1)
    # make sure output files work
    scan2 = Scanner("127.0.0.1", config=bbot_config, output_modules=["json"], name="python_api_test")
    scan2.start_without_generator()
    out_file = scan2.helpers.scans_dir / "python_api_test" / "output.json"
    assert list(scan2.helpers.read_file(out_file))
    # make sure config loads properly
    bbot_home = "/tmp/.bbot_python_api_test"
    Scanner("127.0.0.1", config={"home": bbot_home})
    assert os.environ["BBOT_TOOLS"] == str(Path(bbot_home) / "tools")
