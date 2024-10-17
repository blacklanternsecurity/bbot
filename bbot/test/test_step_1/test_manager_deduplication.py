from ..bbot_fixtures import *  # noqa: F401
from bbot.modules.base import BaseModule


@pytest.mark.asyncio
async def test_manager_deduplication(bbot_scanner):

    class DefaultModule(BaseModule):
        _name = "default_module"
        watched_events = ["DNS_NAME"]

        async def setup(self):
            self.events = []
            return True

        async def handle_event(self, event):
            self.events.append(event)
            await self.emit_event(f"{self.name}.test.notreal", "DNS_NAME", parent=event)

    class EverythingModule(DefaultModule):
        _name = "everything_module"
        watched_events = ["*"]
        scope_distance_modifier = 10
        accept_dupes = True
        suppress_dupes = False

        async def handle_event(self, event):
            self.events.append(event)
            if event.type == "DNS_NAME":
                await self.emit_event(f"{event.data}:88", "OPEN_TCP_PORT", parent=event)

    class NoSuppressDupes(DefaultModule):
        _name = "no_suppress_dupes"
        suppress_dupes = False

    class AcceptDupes(DefaultModule):
        _name = "accept_dupes"
        accept_dupes = True

    class PerHostOnly(DefaultModule):
        _name = "per_hostport_only"
        per_hostport_only = True

    class PerDomainOnly(DefaultModule):
        _name = "per_domain_only"
        per_domain_only = True


    async def do_scan(*args, _config={}, _dns_mock={}, scan_callback=None, **kwargs):
        scan = bbot_scanner(*args, config=_config, **kwargs)
        default_module = DefaultModule(scan)
        everything_module = EverythingModule(scan)
        no_suppress_dupes = NoSuppressDupes(scan)
        accept_dupes = AcceptDupes(scan)
        per_hostport_only = PerHostOnly(scan)
        per_domain_only = PerDomainOnly(scan)
        scan.modules["default_module"] = default_module
        scan.modules["everything_module"] = everything_module
        scan.modules["no_suppress_dupes"] = no_suppress_dupes
        scan.modules["accept_dupes"] = accept_dupes
        scan.modules["per_hostport_only"] = per_hostport_only
        scan.modules["per_domain_only"] = per_domain_only
        if _dns_mock:
            await scan.helpers.dns._mock_dns(_dns_mock)
        if scan_callback is not None:
            scan_callback(scan)
        return (
            [e async for e in scan.async_start()],
            default_module.events,
            everything_module.events,
            no_suppress_dupes.events,
            accept_dupes.events,
            per_hostport_only.events,
            per_domain_only.events,
        )

    dns_mock_chain = {
        "test.notreal": {"A": ["127.0.0.3"]},
        "default_module.test.notreal": {"A": ["127.0.0.3"]},
        "everything_module.test.notreal": {"A": ["127.0.0.4"]},
        "no_suppress_dupes.test.notreal": {"A": ["127.0.0.5"]},
        "accept_dupes.test.notreal": {"A": ["127.0.0.6"]},
        "per_hostport_only.test.notreal": {"A": ["127.0.0.7"]},
        "per_domain_only.test.notreal": {"A": ["127.0.0.8"]},
    }

    # dns search distance = 1, report distance = 0
    events, default_events, all_events, no_suppress_dupes, accept_dupes, per_hostport_only, per_domain_only = await do_scan(
        "test.notreal",
        _config={"dns": {"minimal": False, "search_distance": 1}, "scope": {"report_distance": 0}},
        _dns_mock=dns_mock_chain,
    )

    assert len(events) == 22
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "test.notreal"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "accept_dupes.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "default_module.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "per_domain_only.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "per_hostport_only.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "test.notreal"])
    assert 5 == len([e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "no_suppress_dupes.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "no_suppress_dupes.test.notreal"])

    assert len(default_events) == 6
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes"])
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in default_events if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])

    assert len(all_events) == 27
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in all_events if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.3" and str(e.module) == "A" and e.parent.data == "test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.3" and str(e.module) == "A" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.5" and str(e.module) == "A" and e.parent.data == "no_suppress_dupes.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.6" and str(e.module) == "A" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.7" and str(e.module) == "A" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "IP_ADDRESS" and e.data == "127.0.0.8" and str(e.module) == "A" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "accept_dupes.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "default_module.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "per_domain_only.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "per_hostport_only.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "test.notreal"])
    assert 5 == len([e for e in all_events if e.type == "OPEN_TCP_PORT" and e.data == "no_suppress_dupes.test.notreal:88" and str(e.module) == "everything_module" and e.parent.data == "no_suppress_dupes.test.notreal"])

    assert len(no_suppress_dupes) == 6
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes"])
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in no_suppress_dupes if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])

    assert len(accept_dupes) == 10
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "accept_dupes.test.notreal"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "default_module.test.notreal"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_domain_only.test.notreal"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "per_hostport_only.test.notreal"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes" and e.parent.data == "test.notreal"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in accept_dupes if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])

    assert len(per_hostport_only) == 6
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "accept_dupes.test.notreal" and str(e.module) == "accept_dupes"])
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "default_module.test.notreal" and str(e.module) == "default_module"])
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "no_suppress_dupes.test.notreal" and str(e.module) == "no_suppress_dupes"])
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "per_domain_only.test.notreal" and str(e.module) == "per_domain_only"])
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "per_hostport_only.test.notreal" and str(e.module) == "per_hostport_only"])
    assert 1 == len([e for e in per_hostport_only if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])

    assert len(per_domain_only) == 1
    assert 1 == len([e for e in per_domain_only if e.type == "DNS_NAME" and e.data == "test.notreal" and str(e.module) == "TARGET" and "SCAN:" in e.parent.data["id"]])
