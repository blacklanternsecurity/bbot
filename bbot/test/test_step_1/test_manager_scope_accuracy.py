"""
The tests in this file are a bit unique because they're not intended to test any specific functionality

They are meant to be a thorough baseline of how different modules and BBOT systems interact
Basically, if there is a small change in how scope works, dns resolution, etc., these tests are designed to catch it.
They will show you how your change affects bbot's behavior across a wide range of scans and configurations.

I know they suck but they exist for a reason. If one of these tests is failing for you, it's important to take the time and
understand exactly what changed and why (and whether it's okay) before changing the test to match your results.
"""

from ..bbot_fixtures import *  # noqa: F401

from pytest_httpserver import HTTPServer


@pytest.fixture
def bbot_other_httpservers():

    server_hosts = [
        ("127.0.0.77", 8888),
        ("127.0.0.88", 8888),
        ("127.0.0.99", 8888),
        ("127.0.0.111", 8888),
        ("127.0.0.222", 8889),
        ("127.0.0.33", 8889),
    ]

    servers = [HTTPServer(host=host, port=port, threaded=True) for host, port in server_hosts]
    for server in servers:
        server.start()

    yield servers

    for server in servers:
        server.clear()
        if server.is_running():
            server.stop()
        server.check_assertions()
        server.clear()



@pytest.mark.asyncio
async def test_manager_scope_accuracy(bbot_scanner, bbot_httpserver, bbot_other_httpservers, bbot_httpserver_ssl):
    """
    This test ensures that BBOT correctly handles different scope distance settings.
    It performs these tests for normal modules, output modules, and their graph variants,
    ensuring that when an internal event leads to an interesting discovery, the entire event chain is preserved.
    This is important for preventing orphans in the graph.
    """

    from bbot.modules.base import BaseModule
    from bbot.modules.output.base import BaseOutputModule

    server_77, server_88, server_99, server_111, server_222, server_33 = bbot_other_httpservers

    bbot_httpserver.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.77:8888'/>")
    server_77.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.88:8888'/>")
    server_88.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.99:8888'/>")
    server_99.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.111:8888'/>")
    server_111.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.222:8889'/><a href='http://127.0.0.33:8889'/>")
    server_222.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.44:8888'/>")
    server_33.expect_request(uri="/").respond_with_data(response_data="<a href='http://127.0.0.55:8888'/>")

    class DummyModule(BaseModule):
        _name = "dummy_module"
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

    class DummyGraphOutputModule(BaseOutputModule):
        _name = "dummy_graph_output_module"
        watched_events = ["*"]
        _preserve_graph = True

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)

    class DummyGraphBatchOutputModule(DummyGraphOutputModule):
        _name = "dummy_graph_batch_output_module"
        watched_events = ["*"]
        _preserve_graph = True
        batch_size = 5

        async def handle_batch(self, *events):
            for event in events:
                self.events.append(event)

    async def do_scan(*args, _config={}, _dns_mock={}, scan_callback=None, **kwargs):
        scan = bbot_scanner(*args, config=_config, **kwargs)
        dummy_module = DummyModule(scan)
        dummy_module_nodupes = DummyModuleNoDupes(scan)
        dummy_graph_output_module = DummyGraphOutputModule(scan)
        dummy_graph_batch_output_module = DummyGraphBatchOutputModule(scan)
        scan.modules["dummy_module"] = dummy_module
        scan.modules["dummy_module_nodupes"] = dummy_module_nodupes
        scan.modules["dummy_graph_output_module"] = dummy_graph_output_module
        scan.modules["dummy_graph_batch_output_module"] = dummy_graph_batch_output_module
        await scan.helpers.dns._mock_dns(_dns_mock)
        if scan_callback is not None:
            scan_callback(scan)
        return (
            [e async for e in scan.async_start()],
            dummy_module.events,
            dummy_module_nodupes.events,
            dummy_graph_output_module.events,
            dummy_graph_batch_output_module.events,
        )

    dns_mock_chain = {
        "test.notreal": {"A": ["127.0.0.66"]},
        "66.0.0.127.in-addr.arpa": {"PTR": ["test.notrealzies"]},
        "test.notrealzies": {"CNAME": ["www.test.notreal"]},
        "www.test.notreal": {"A": ["127.0.0.77"]},
        "77.0.0.127.in-addr.arpa": {"PTR": ["test2.notrealzies"]},
        "test2.notrealzies": {"A": ["127.0.0.88"]},
    }

    # dns search distance = 1, report distance = 0
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        _config={"dns": {"minimal": False, "search_distance": 1}, "scope": {"report_distance": 0}},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 2
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    for _all_events in (all_events, all_events_nodups):
        assert len(_all_events) == 3
        assert 1 == len([e for e in _all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == True and e.scope_distance == 1])
        assert 0 == len([e for e in _all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
        assert 0 == len([e for e in _all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
        assert 0 == len([e for e in _all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    assert len(graph_output_events) == 2
    assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal"])
    assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])

    # dns search distance = 2, report distance = 0
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        _config={"dns": {"minimal": False, "search_distance": 2}, "scope": {"report_distance": 0}},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 3
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events) == 9
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == True and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 0 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events_nodups) == 7
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 0 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 5
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == True and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
        assert 0 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    # dns search distance = 2, report distance = 1
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        _config={"dns": {"minimal": False, "search_distance": 2}, "scope": {"report_distance": 1}},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 6
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events) == 8
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 0 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    assert len(all_events_nodups) == 7
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test2.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 0 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 6
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "www.test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test2.notrealzies"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])

    dns_mock_chain = {
        "test.notreal": {"A": ["127.0.0.66"]},
        "66.0.0.127.in-addr.arpa": {"PTR": ["test.notrealzies"]},
        "test.notrealzies": {"A": ["127.0.0.77"]},
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
            await self.emit_event(
                {"host": str(event.host), "description": "yep", "severity": "CRITICAL"}, "VULNERABILITY", parent=event
            )

    def custom_setup(scan):
        dummyvulnmodule = DummyVulnModule(scan)
        scan.modules["dummyvulnmodule"] = dummyvulnmodule

    # dns search distance = 3, report distance = 1
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        scan_callback=custom_setup,
        _config={"dns": {"minimal": False, "search_distance": 3}, "scope": {"report_distance": 1}},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 4
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notrealzies"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77"])
    assert 1 == len([e for e in events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e.internal == False and e.scope_distance == 3])

    assert len(all_events) == 8
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e.internal == False and e.scope_distance == 3])

    assert len(all_events_nodups) == 6
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events_nodups if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e.internal == False and e.scope_distance == 3])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 6
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.66" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notrealzies" and e.internal == True and e.scope_distance == 2])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == True and e.scope_distance == 3])
        assert 1 == len([e for e in _graph_output_events if e.type == "VULNERABILITY" and e.data["host"] == "127.0.0.77" and e.internal == False and e.scope_distance == 3])

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 0
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx"],
        _config={
            "dns": {"minimal": False, "search_distance": 2},
            "scope": {"report_distance": 1, "search_distance": 0},
            "speculate": True,
            "excavate": True,
            "modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
        _dns_mock={},
    )

    assert len(events) == 6
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])

    assert len(all_events) == 14
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1 and "spider-danger" in e.tags])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])

    assert len(all_events_nodups) == 12
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1 and "spider-danger" in e.tags])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 6
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 0, in_scope_only = False
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx"],
        output_modules=["neo4j"],
        _config={
            "dns": {"minimal": False, "search_distance": 2},
            "scope": {"search_distance": 0, "report_distance": 1},
            "excavate": True,
            "speculate": True,
            "modules": {"httpx": {"in_scope_only": False}, "speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 7
    # 2024-08-01
    # Removed OPEN_TCP_PORT("127.0.0.77:8888")
    # before, this event was speculated off the URL_UNVERIFIED, and that's what was used by httpx to generate the URL. it was graph-important.
    # now for whatever reason, httpx is visiting the url directly and the open port isn't being used
    # I don't know what changed exactly, but it doesn't matter, either way is equally valid and bbot is meant to be flexible this way.
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])

    assert len(all_events) == 18
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])

    assert len(all_events_nodups) == 16
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1 and "spider-danger" in e.tags])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 7
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and "spider-danger" in e.tags])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/"])

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 1
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx"],
        _config={
            "dns": {"minimal": False, "search_distance": 2},
            "scope": {"report_distance": 1, "search_distance": 1},
            "excavate": True,
            "speculate": True,
            "modules": {"httpx": {"in_scope_only": False}, "speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 7
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])

    assert len(all_events) == 23
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1 and "spider-danger" in e.tags])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.99:8888/" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.99" and e.internal == True and e.scope_distance == 3])

    assert len(all_events_nodups) == 21
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1 and "spider-danger" in e.tags])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.99:8888/" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.99" and e.internal == True and e.scope_distance == 3])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 7
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.77:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/"])

    # 2 events from a single HTTP_RESPONSE
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.111/31",
        whitelist=["127.0.0.111/31", "127.0.0.222", "127.0.0.33"],
        modules=["httpx"],
        output_modules=["python"],
        _config={
            "dns": {"minimal": False, "search_distance": 2},
            "scope": {"search_distance": 0, "report_distance": 0},
            "excavate": True,
            "speculate": True,
            "modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 9
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.111:8888/"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.222:8889"])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.33:8889"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.44"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.55"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888"])

    assert len(all_events) == 29
    for e in all_events:
        log.critical(e)
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.44" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.55" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888" and e.internal == True and e.scope_distance == 1])

    assert len(all_events_nodups) == 27
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.110" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["url"] == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.44" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.55" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888" and e.internal == True and e.scope_distance == 1])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 9
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.111:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889"])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.222:8889"])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.33:8889"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.44"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.55"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888"])

    # sslcert with in-scope chain
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.0/31",
        modules=["sslcert"],
        _config={"scope": {"report_distance": 0}, "speculate": True, "modules": {"speculate": {"ports": "9999"}}},
        _dns_mock={"www.bbottest.notreal": {"A": ["127.0.1.0"]}, "test.notreal": {"A": ["127.0.0.1"]}},
    )

    assert len(events) == 6
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == False and e.scope_distance == 1 and str(e.module) == "sslcert" and "affiliate" in e.tags])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal"])

    assert len(all_events) == 13
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == False and e.scope_distance == 1 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "www.bbottest.notreal:9999" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "bbottest.notreal" and e.internal == True and e.scope_distance == 2 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])

    assert len(all_events_nodups) == 11
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == False and e.scope_distance == 1 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "www.bbottest.notreal:9999" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME_UNRESOLVED" and e.data == "bbottest.notreal" and e.internal == True and e.scope_distance == 2 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 6
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
        assert 1 == len([e for e in _graph_output_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == False and e.scope_distance == 1 and str(e.module) == "sslcert"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "www.bbottest.notreal:9999"])
        assert 0 == len([e for e in _graph_output_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "bbottest.notreal"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])

    # sslcert with out-of-scope chain
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.0/31",
        modules=["sslcert"],
        whitelist=["127.0.1.0"],
        _config={"scope": {"search_distance": 1, "report_distance": 0}, "speculate": True, "modules": {"speculate": {"ports": "9999"}}},
        _dns_mock={"www.bbottest.notreal": {"A": ["127.0.0.1"]}, "test.notreal": {"A": ["127.0.1.0"]}},
    )

    assert len(events) == 3
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])

    assert len(all_events) == 11
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 2])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 2])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == True and e.scope_distance == 3 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])

    assert len(all_events_nodups) == 9
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == True and e.scope_distance == 3 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 5
        assert 1 == len([e for e in graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 2])
        assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
        assert 1 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
        assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
        assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal"])
        assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])


@pytest.mark.asyncio
async def test_manager_blacklist(bbot_scanner, bbot_httpserver, caplog):

    bbot_httpserver.expect_request(uri="/").respond_with_data(response_data="<a href='http://www-prod.test.notreal:8888'/><a href='http://www-dev.test.notreal:8888'/>")

    # dns search distance = 1, report distance = 0
    scan = bbot_scanner(
        "http://127.0.0.1:8888",
        modules=["httpx"],
        config={"excavate": True, "dns": {"minimal": False, "search_distance": 1}, "scope": {"report_distance": 0}},
        whitelist=["127.0.0.0/29", "test.notreal"],
        blacklist=["127.0.0.64/29"],
    )
    await scan.helpers.dns._mock_dns({
        "www-prod.test.notreal": {"A": ["127.0.0.66"]},
        "www-dev.test.notreal": {"A": ["127.0.0.22"]},
    })

    events = [e async for e in scan.async_start()]

    assert any([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://www-dev.test.notreal:8888/"])
    # the hostname is in-scope, but its IP is blacklisted, therefore we shouldn't see it
    assert not any([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://www-prod.test.notreal:8888/"])

    assert 'Not forwarding DNS_NAME("www-prod.test.notreal", module=excavate' in caplog.text and 'because it has a blacklisted DNS record' in caplog.text


@pytest.mark.asyncio
async def test_manager_scope_tagging(bbot_scanner):
    scan = bbot_scanner("test.notreal")
    e1 = scan.make_event("www.test.notreal", parent=scan.root_event, tags=["affiliate"])
    assert e1.scope_distance == 1
    assert "distance-1" in e1.tags
    assert "affiliate" in e1.tags

    e2 = scan.make_event("dev.test.notreal", parent=e1, tags=["affiliate"])
    assert e2.scope_distance == 2
    assert "affiliate" in e2.tags
    assert "in-scope" not in e2.tags
    distance_tags = [t for t in e2.tags if t.startswith("distance-")]
    assert len(distance_tags) == 1
    assert distance_tags[0] == "distance-2"

    e2.scope_distance = 0
    assert e2.scope_distance == 0
    assert "in-scope" in e2.tags
    assert "affiliate" not in e2.tags
    distance_tags = [t for t in e2.tags if t.startswith("distance-")]
    assert not distance_tags

    await scan._cleanup()
