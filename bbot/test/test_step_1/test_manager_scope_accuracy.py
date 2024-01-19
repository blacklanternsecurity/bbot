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

    servers = [HTTPServer(host=host, port=port) for host, port in server_hosts]
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
async def test_manager_scope_accuracy(bbot_config, bbot_scanner, bbot_httpserver, bbot_other_httpservers, bbot_httpserver_ssl):
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
        merged_config = OmegaConf.merge(bbot_config, OmegaConf.create(_config))
        scan = bbot_scanner(*args, config=merged_config, **kwargs)
        dummy_module = DummyModule(scan)
        dummy_module_nodupes = DummyModuleNoDupes(scan)
        dummy_graph_output_module = DummyGraphOutputModule(scan)
        dummy_graph_batch_output_module = DummyGraphBatchOutputModule(scan)
        scan.modules["dummy_module"] = dummy_module
        scan.modules["dummy_module_nodupes"] = dummy_module_nodupes
        scan.modules["dummy_graph_output_module"] = dummy_graph_output_module
        scan.modules["dummy_graph_batch_output_module"] = dummy_graph_batch_output_module
        if _dns_mock:
            scan.helpers.dns.mock_dns(_dns_mock)
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
        ("test.notreal", "A"): "127.0.0.66",
        ("127.0.0.66", "PTR"): "test.notrealzies",
        ("test.notrealzies", "CNAME"): "www.test.notreal",
        ("www.test.notreal", "A"): "127.0.0.77",
        ("127.0.0.77", "PTR"): "test2.notrealzies",
        ("test2.notrealzies", "A"): "127.0.0.88",
    }

    # dns search distance = 1, report distance = 0
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        _config={"dns_resolution": True, "scope_dns_search_distance": 1, "scope_report_distance": 0},
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
        _config={"dns_resolution": True, "scope_dns_search_distance": 2, "scope_report_distance": 0},
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
        _config={"dns_resolution": True, "scope_dns_search_distance": 2, "scope_report_distance": 1},
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
            await self.emit_event(
                {"host": str(event.host), "description": "yep", "severity": "CRITICAL"}, "VULNERABILITY", source=event
            )

    def custom_setup(scan):
        dummyvulnmodule = DummyVulnModule(scan)
        scan.modules["dummyvulnmodule"] = dummyvulnmodule

    # dns search distance = 3, report distance = 1
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "test.notreal",
        scan_callback=custom_setup,
        _config={"dns_resolution": True, "scope_dns_search_distance": 3, "scope_report_distance": 1},
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

    assert len(events) == 6
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])

    assert len(all_events) == 13
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == True and e.scope_distance == 1])

    assert len(all_events_nodups) == 11
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
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
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888"])

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 0, in_scope_only = False
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.1/31",
        modules=["httpx", "excavate"],
        _config={
            "scope_search_distance": 0,
            "scope_dns_search_distance": 2,
            "scope_report_distance": 1,
            "speculate": True,
            "modules": {"httpx": {"in_scope_only": False}},
            "internal_modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 8
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
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
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])

    assert len(all_events_nodups) == 15
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 8
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/"])

    # httpx/speculate IP_RANGE --> IP_ADDRESS --> OPEN_TCP_PORT --> URL, search distance = 1
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
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

    assert len(events) == 8
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
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
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.99:8888/" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.99" and e.internal == True and e.scope_distance == 3])

    assert len(all_events_nodups) == 20
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.88" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.88:8888/" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.88:8888" and e.internal == True and e.scope_distance == 2])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.99:8888/" and e.internal == True and e.scope_distance == 3])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.99" and e.internal == True and e.scope_distance == 3])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 8
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.1:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.77:8888/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.77" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.77:8888" and e.internal == False and e.scope_distance == 1])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.77:8888/" and e.internal == False and e.scope_distance == 1])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.77:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.88"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.88:8888/"])

    # 2 events from a single HTTP_RESPONSE
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.111/31",
        whitelist=["127.0.0.111/31", "127.0.0.222", "127.0.0.33"],
        modules=["httpx", "excavate"],
        output_modules=["python"],
        _config={
            "scope_search_distance": 0,
            "scope_dns_search_distance": 2,
            "scope_report_distance": 0,
            "speculate": True,
            "internal_modules": {"speculate": {"ports": "8888"}},
            "omit_event_types": ["HTTP_RESPONSE", "URL_UNVERIFIED"],
        },
    )

    assert len(events) == 11
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/" and e.internal == True and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.44" and e.internal == True and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/" and e.internal == True and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.55" and e.internal == True and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888" and e.internal == True and e.scope_distance == 1])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888" and e.internal == True and e.scope_distance == 1])

    assert len(all_events) == 30
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888" and e.internal == True and e.scope_distance == 0])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.44" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.55" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888" and e.internal == True and e.scope_distance == 1])

    assert len(all_events_nodups) == 26
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.110" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.222" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.33" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888" and e.internal == True and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.222:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL" and e.data == "http://127.0.0.33:8889/" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.44:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.44" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.55:8888/" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.55" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.44:8888" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.55:8888" and e.internal == True and e.scope_distance == 1])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 11
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.110/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.110"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.111" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.110:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.111:8888" and e.internal == False and e.scope_distance == 0])
        assert 1 == len([e for e in _graph_output_events if e.type == "URL" and e.data == "http://127.0.0.111:8888/" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "HTTP_RESPONSE" and e.data["input"] == "127.0.0.111:8888"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.222:8889/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.222"])
        assert 0 == len([e for e in _graph_output_events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.33:8889/"])
        assert 1 == len([e for e in _graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.33"])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.222:8889" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8888"])
        assert 1 == len([e for e in _graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.33:8889" and e.internal == False and e.scope_distance == 0])
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
        modules=["speculate", "sslcert"],
        _config={"dns_resolution": False, "scope_report_distance": 0, "internal_modules": {"speculate": {"ports": "9999"}}},
        _dns_mock={("www.bbottest.notreal", "A"): "127.0.1.0", ("test.notreal", "A"): "127.0.0.1"},
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

    assert len(all_events) == 14
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
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])

    assert len(all_events_nodups) == 12
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
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])

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
        assert 0 == len([e for e in _graph_output_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal"])

    # sslcert with out-of-scope chain
    events, all_events, all_events_nodups, graph_output_events, graph_output_batch_events = await do_scan(
        "127.0.0.0/31",
        modules=["speculate", "sslcert"],
        whitelist=["127.0.1.0"],
        _config={"dns_resolution": False, "scope_report_distance": 0, "internal_modules": {"speculate": {"ports": "9999"}}},
        _dns_mock={("www.bbottest.notreal", "A"): "127.0.0.1", ("test.notreal", "A"): "127.0.1.0"},
    )

    assert len(events) == 3
    assert 1 == len([e for e in events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
    assert 0 == len([e for e in events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal"])
    assert 0 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])
    assert 0 == len([e for e in events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal"])

    assert len(all_events) == 12
    assert 1 == len([e for e in all_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 1])
    assert 2 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == True and e.scope_distance == 2 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])

    assert len(all_events_nodups) == 10
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.0" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal" and e.internal == True and e.scope_distance == 2 and str(e.module) == "sslcert"])
    assert 1 == len([e for e in all_events_nodups if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999" and e.internal == True and e.scope_distance == 0 and str(e.module) == "speculate"])
    assert 1 == len([e for e in all_events_nodups if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal" and e.internal == True and e.scope_distance == 1 and str(e.module) == "speculate"])

    for _graph_output_events in (graph_output_events, graph_output_batch_events):
        assert len(_graph_output_events) == 5
        assert 1 == len([e for e in graph_output_events if e.type == "IP_RANGE" and e.data == "127.0.0.0/31" and e.internal == False and e.scope_distance == 0])
        assert 0 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.0"])
        assert 1 == len([e for e in graph_output_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.internal == True and e.scope_distance == 1])
        assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.0:9999"])
        assert 1 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "127.0.0.1:9999" and e.internal == True and e.scope_distance == 1])
        assert 1 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "test.notreal" and e.internal == False and e.scope_distance == 0 and str(e.module) == "sslcert"])
        assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME" and e.data == "www.bbottest.notreal"])
        assert 0 == len([e for e in graph_output_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:9999"])
        assert 0 == len([e for e in graph_output_events if e.type == "DNS_NAME_UNRESOLVED" and e.data == "notreal"])


@pytest.mark.asyncio
async def test_manager_blacklist(bbot_config, bbot_scanner, bbot_httpserver, caplog):

    bbot_httpserver.expect_request(uri="/").respond_with_data(response_data="<a href='http://www-prod.test.notreal:8888'/><a href='http://www-dev.test.notreal:8888'/>")

    # dns search distance = 1, report distance = 0
    config = {"dns_resolution": True, "scope_dns_search_distance": 1, "scope_report_distance": 0}
    merged_config = OmegaConf.merge(bbot_config, OmegaConf.create(config))
    scan = bbot_scanner(
        "http://127.0.0.1:8888",
        modules=["httpx", "excavate"],
        config=merged_config,
        whitelist=["127.0.0.0/29", "test.notreal"],
        blacklist=["127.0.0.64/29"],
    )
    scan.helpers.dns.mock_dns({
        ("www-prod.test.notreal", "A"): "127.0.0.66",
        ("www-dev.test.notreal", "A"): "127.0.0.22",
    })

    events = [e async for e in scan.async_start()]

    assert any([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://www-dev.test.notreal:8888/"])
    assert not any([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://www-prod.test.notreal:8888/"])

    assert 'Omitting due to blacklisted DNS associations: URL_UNVERIFIED("http://www-prod.test.notreal:8888/"' in caplog.text


@pytest.mark.asyncio
async def test_manager_scope_tagging(bbot_config, bbot_scanner):
    scan = bbot_scanner("test.notreal", config=bbot_config)
    e1 = scan.make_event("www.test.notreal", source=scan.root_event, tags=["affiliate"])
    assert e1.scope_distance == 1
    assert "distance-1" in e1.tags
    assert "affiliate" in e1.tags

    e2 = scan.make_event("dev.test.notreal", source=e1, tags=["affiliate"])
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
