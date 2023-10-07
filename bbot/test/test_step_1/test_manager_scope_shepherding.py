from ..bbot_fixtures import *  # noqa: F401

from pytest_httpserver import HTTPServer


@pytest.fixture
def bbot_other_httpserver():
    server = HTTPServer(host="127.0.0.77", port=8888)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    server.check_assertions()
    server.clear()


@pytest.fixture
def bbot_other_httpserver2():
    server = HTTPServer(host="127.0.0.88", port=8888)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    server.check_assertions()
    server.clear()


@pytest.fixture
def bbot_other_httpserver3():
    server = HTTPServer(host="127.0.0.111", port=8888)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    server.check_assertions()
    server.clear()


@pytest.fixture
def bbot_other_httpserver4():
    server = HTTPServer(host="127.0.0.222", port=8888)
    server.start()

    yield server

    server.clear()
    if server.is_running():
        server.stop()

    server.check_assertions()
    server.clear()




@pytest.mark.asyncio
async def test_manager_scope_shepherding(bbot_config, bbot_scanner, bbot_httpserver, bbot_other_httpserver, bbot_other_httpserver2, bbot_other_httpserver3, bbot_other_httpserver4):
    from bbot.modules.base import BaseModule
    from bbot.modules.output.base import BaseOutputModule

    class DummyModule(BaseModule):
        _name = "dummymodule"
        watched_events = ["*"]
        scope_distance_modifier = 10
        accept_dupes = True

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)

    class DummyModuleNoDupes(DummyModule):
        accept_dupes = False

    class DummyGraphModule(DummyModule):
        _name = "dummygraphmodule"
        watched_events = ["*"]
        scope_distance_modifier = 0
        accept_dupes = True
        _preserve_graph = True

    class DummyGraphOutputModule(BaseOutputModule):
        _name = "dummygraphoutputmodule"
        watched_events = ["*"]
        _preserve_graph = True

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)

    async def do_scan(*args, _config={}, _dns_mock={}, scan_callback=None, **kwargs):
        merged_config = OmegaConf.merge(bbot_config, OmegaConf.create(_config))
        scan = bbot_scanner(*args, config=merged_config, **kwargs)
        dummymodule = DummyModule(scan)
        dummymodulenodupes = DummyModuleNoDupes(scan)
        dummygraphmodule = DummyGraphModule(scan)
        dummygraphoutputmodule = DummyGraphOutputModule(scan)
        scan.modules["dummymodule"] = dummymodule
        scan.modules["dummymodulenodupes"] = dummymodulenodupes
        scan.modules["dummygraphmodule"] = dummygraphmodule
        scan.modules["dummygraphoutputmodule"] = dummygraphoutputmodule
        if _dns_mock:
            scan.helpers.dns.mock_dns(_dns_mock)
        if scan_callback is not None:
            scan_callback(scan)
        return (
            [e async for e in scan.async_start()],
            dummymodule.events,
            dummymodulenodupes.events,
            dummygraphmodule.events,
            dummygraphoutputmodule.events,
        )

    dns_mock_chain = {
        ("test.notreal", "A"): "127.0.0.66",
        ("127.0.0.66", "PTR"): "test.notrealzies",
        ("test.notrealzies", "CNAME"): "www.test.notreal",
        ("www.test.notreal", "A"): "127.0.0.77",
        ("127.0.0.77", "PTR"): "test2.notrealzies",
        ("test2.notrealzies", "A"): "127.0.0.88",
    }

    """

    # dns search distance = 1, report distance = 0
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "test.notreal",
        _config={"dns_resolution": True, "scope_dns_search_distance": 1, "scope_report_distance": 0},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 2
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    assert len(all_events) == 3
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    assert len(all_events_nodups) == 3
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    assert len(graph_events) == 2
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    assert len(graph_output_events) == 2
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    """

    # dns search distance = 2, report distance = 0
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "test.notreal",
        _config={"dns_resolution": True, "scope_dns_search_distance": 2, "scope_report_distance": 0},
        _dns_mock=dns_mock_chain,
    )

    for e in events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events_nodups:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_output_events:
        log.critical(e)

    assert len(events) == 3
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events) == 7
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events_nodups) == 7
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(graph_events) == 5
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(graph_output_events) == 5
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    return

    """

    # dns search distance = 2, report distance = 1
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "test.notreal",
        _config={"dns_resolution": True, "scope_dns_search_distance": 2, "scope_report_distance": 1},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 5
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events) == 7
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events_nodups) == 7
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(graph_events) == 5
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(graph_output_events) == 7
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 2 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    dns_mock_chain = {
        ("test.notreal", "A"): "127.0.0.66",
        ("127.0.0.66", "PTR"): "test.notrealzies",
        ("test.notrealzies", "A"): "127.0.0.77",
    }

    class DummyVulnModule(BaseModule):
        _name = "dummyvulnmodule"
        watched_events = ["IP_ADDRESS"]
        scope_distance_modifier = 3
        accept_dupes = True

        async def filter_event(self, event):
            if event.data == "127.0.0.77":
                return True
            return False, "bleh"

        async def handle_event(self, event):
            self.emit_event(
                {"host": str(event.host), "description": "yep", "severity": "CRITICAL"}, "VULNERABILITY", source=event
            )

    def custom_setup(scan):
        dummyvulnmodule = DummyVulnModule(scan)
        scan.modules["dummyvulnmodule"] = dummyvulnmodule

    # dns search distance = 3, report distance = 1
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "test.notreal",
        scan_callback=custom_setup,
        _config={"dns_resolution": True, "scope_dns_search_distance": 3, "scope_report_distance": 1},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 4
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 1 == len([e for e in events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e._internal == False and e._graph_important == False])

    assert len(all_events) == 6
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e._internal == False and e._graph_important == False])

    assert len(all_events_nodups) == 6
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e._internal == False and e._graph_important == False])

    assert len(graph_events) == 5
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == True])
    assert 0 == len([e for e in graph_events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77"])

    assert len(graph_output_events) == 7
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e._internal == False and e._graph_important == False])
    assert 2 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e._internal == False and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e._internal == False and e._graph_important == False])
    """

    bbot_httpserver.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.77:8888'/>")
    bbot_other_httpserver.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.88:8888'/>")
    bbot_other_httpserver2.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.99:8888'/>")
    bbot_other_httpserver3.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.111:8888'/>")
    bbot_other_httpserver4.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.222:8888'/>")

    """

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 0
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx", "excavate"],
        _config={
            "scope_search_distance": 0,
            "scope_dns_search_distance": 2,
            "scope_report_distance": 1,
            "speculate": True,
            "internal_modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 3
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])

    assert len(all_events) == 11
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])

    assert len(all_events_nodups) == 11
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])

    assert len(graph_events) == 10
    assert 1 == len([e for e in graph_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])

    assert len(graph_output_events) == 5
    assert 1 == len([e for e in graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])

    """

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 0
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx", "excavate"],
        output_modules=["neo4j"],
        _config={
            "scope_search_distance": 0,
            "scope_dns_search_distance": 2,
            "scope_report_distance": 1,
            "speculate": True,
            "modules": {"httpx": {"in_scope_only": False}},
            "internal_modules": {"speculate": {"ports": "8888"}},
            "output_modules": {"neo4j": {"uri": "bolt://localhost:7687"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    for e in events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events_nodups:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_output_events:
        log.critical(e)

    assert len(events) == 4
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])

    assert len(all_events) == 15
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(all_events_nodups) == 15
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(graph_events) == 10
    assert 1 == len([e for e in graph_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(graph_output_events) == 6
    assert 1 == len([e for e in graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    return

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 1
    events, all_events, all_events_nodups, graph_events, graph_output_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx", "excavate"],
        _config={
            "scope_search_distance": 1,
            "scope_dns_search_distance": 2,
            "scope_report_distance": 1,
            "speculate": True,
            "modules": {"httpx": {"in_scope_only": False}},
            "internal_modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    for e in events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in all_events_nodups:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_events:
        log.critical(e)
    log.critical("=" * 20)
    for e in graph_output_events:
        log.critical(e)

    assert len(events) == 4
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])

    return

    assert len(all_events) == 15
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(all_events_nodups) == 15
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(graph_events) == 10
    assert 1 == len([e for e in graph_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 2 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 1 == len([e for e in graph_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])

    assert len(graph_output_events) == 5
    assert 1 == len([e for e in graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e._internal == True and e._graph_important == True])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e._internal == True and e._graph_important == False])
    assert 1 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e._internal == True and e._graph_important == True])
    assert 1 == len([e for e in graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e._internal == False and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e._internal == True and e._graph_important == False])
    assert 0 == len([e for e in graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e._internal == True and e._graph_important == False])
