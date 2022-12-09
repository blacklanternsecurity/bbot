from time import sleep

from ..bbot_fixtures import *  # noqa: F401


def test_agent(agent):
    agent.start()
    agent.on_error(agent.ws, "test")
    agent.on_close(agent.ws, "test", "test")
    agent.on_open(agent.ws)
    agent.on_message(
        agent.ws,
        '{"conversation": "90196cc1-299f-4555-82a0-bc22a4247590", "command": "start_scan", "arguments": {"scan_id": "90196cc1-299f-4555-82a0-bc22a4247590", "targets": ["www.blacklanternsecurity.com"], "modules": ["ipneighbor"], "output_modules": ["human"]}}',
    )
    sleep(0.5)
    agent.scan_status()
    agent.stop_scan()
