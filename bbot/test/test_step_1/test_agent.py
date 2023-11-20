import json
import websockets
from functools import partial

from ..bbot_fixtures import *  # noqa: F401


_first_run = True
success = False


async def websocket_handler(websocket, path, scan_done=None):
    # whether this is the first run
    global _first_run
    first_run = int(_first_run)
    # whether the test succeeded
    global success
    # test phase
    phase = "ping"
    # control channel or event channel?
    control = True

    if path == "/control/" and first_run:
        # test ping
        await websocket.send(json.dumps({"conversation": "90196cc1-299f-4555-82a0-bc22a4247590", "command": "ping"}))
        _first_run = False
    else:
        control = False

    # Bearer token
    assert websocket.request_headers["Authorization"] == "Bearer test"

    async for message in websocket:
        log.debug(f"PHASE: {phase}, MESSAGE: {message}")
        if not control or not first_run:
            continue
        m = json.loads(message)
        # ping
        if phase == "ping":
            assert json.loads(message)["message_type"] == "pong"
            phase = "start_scan_bad"
        if phase == "start_scan_bad":
            await websocket.send(
                json.dumps(
                    {
                        "conversation": "90196cc1-299f-4555-82a0-bc22a4247590",
                        "command": "start_scan",
                        "arguments": {
                            "scan_id": "90196cc1-299f-4555-82a0-bc22a4247590",
                            "targets": ["127.0.0.2"],
                            "modules": ["asdf"],
                            "output_modules": ["human"],
                            "name": "agent_test_scan_bad",
                        },
                    }
                )
            )
            phase = "success"
            continue
        # scan start success
        if phase == "success":
            assert m["message"]["success"] == "Started scan"
            phase = "cleaning_up"
            continue
        # CLEANING_UP status message
        if phase == "cleaning_up":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "CLEANING_UP"
            phase = "failed"
            continue
        # FAILED status message
        if phase == "failed":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "FAILED"
            phase = "start_scan"
        # start good scan
        if phase == "start_scan":
            await websocket.send(
                json.dumps(
                    {
                        "conversation": "90196cc1-299f-4555-82a0-bc22a4247590",
                        "command": "start_scan",
                        "arguments": {
                            "scan_id": "90196cc1-299f-4555-82a0-bc22a4247590",
                            "targets": ["127.0.0.2"],
                            "modules": ["ipneighbor"],
                            "output_modules": ["human"],
                            "name": "agent_test_scan",
                        },
                    }
                )
            )
            phase = "success_2"
            continue
        # scan start success
        if phase == "success_2":
            assert m["message"]["success"] == "Started scan"
            phase = "starting"
            continue
        # STARTING status message
        if phase == "starting":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "STARTING"
            phase = "running"
            continue
        # RUNNING status message
        if phase == "running":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "RUNNING"
            phase = "finishing"
            continue
        # FINISHING status message
        if phase == "finishing":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "FINISHING"
            phase = "cleaning_up_2"
            continue
        # CLEANING_UP status message
        if phase == "cleaning_up_2":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "CLEANING_UP"
            phase = "finished_2"
            continue
        # FINISHED status message
        if phase == "finished_2":
            assert m["message_type"] == "scan_status_change"
            assert m["status"] == "FINISHED"
            success = True
            scan_done.set()
            break


@pytest.mark.asyncio
async def test_agent(agent):
    scan_done = asyncio.Event()
    scan_status = await agent.scan_status()
    assert scan_status["error"] == "Scan not in progress"

    _websocket_handler = partial(websocket_handler, scan_done=scan_done)

    global success
    async with websockets.serve(_websocket_handler, "127.0.0.1", 8765):
        agent_task = asyncio.create_task(agent.start())
        # wait for 90 seconds
        await asyncio.wait_for(scan_done.wait(), 60)
        assert success

        await agent.start_scan("scan_to_be_cancelled", targets=["127.0.0.1"], modules=["ipneighbor"])
        await agent.start_scan("scan_to_be_rejected", targets=["127.0.0.1"], modules=["ipneighbor"])
        await asyncio.sleep(0.1)
        await agent.stop_scan()
        tasks = [agent.task, agent_task]
        for task in tasks:
            try:
                task.cancel()
                await task
            except (asyncio.CancelledError, AttributeError):
                pass
