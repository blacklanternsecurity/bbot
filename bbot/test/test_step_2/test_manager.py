from ..bbot_fixtures import *  # noqa: F401


def test_manager(bbot_config, bbot_scanner):
    dns_config = OmegaConf.merge(default_config, OmegaConf.create({"dns_resolution": True}))

    # test _emit_event
    results = []
    success_callback = lambda e: results.append("success")
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor"], config=dns_config)
    scan1.status = "RUNNING"
    manager = scan1.manager
    manager.distribute_event = lambda e: results.append(e)
    localhost = scan1.make_event("127.0.0.1", source=scan1.root_event)

    class DummyModule1:
        _type = "output"
        suppress_dupes = True

    class DummyModule2:
        _type = "DNS"
        suppress_dupes = True

    localhost.module = DummyModule1()
    # test abort_if
    manager._emit_event(localhost, abort_if=lambda e: e.module._type == "output")
    assert len(results) == 0
    manager.events_accepted.clear()
    manager._emit_event(
        localhost, on_success_callback=success_callback, abort_if=lambda e: e.module._type == "plumbus"
    )
    assert localhost in results
    assert "success" in results
    results.clear()
    # test deduplication
    manager._emit_event(localhost, on_success_callback=success_callback)
    assert len(results) == 0
    # test dns resolution
    googledns = scan1.make_event("8.8.8.8", source=scan1.root_event)
    googledns.module = DummyModule2()
    googledns.source = "asdf"
    googledns.make_in_scope()
    event_children = []
    manager.emit_event = lambda e, *args, **kwargs: event_children.append(e)
    manager._emit_event(googledns)
    assert len(event_children) > 0
    assert googledns in results
    results.clear()
    event_children.clear()
    # same dns event
    manager._emit_event(googledns)
    assert len(results) == 0
    assert len(event_children) == 0
    # same dns event but with _force_output
    googledns._force_output = True
    manager._emit_event(googledns)
    assert googledns in results
    assert len(event_children) == 0
    googledns._force_output = False
    results.clear()
    # same dns event but different source
    source_event = manager.scan.make_event("1.2.3.4", "IP_ADDRESS", source=manager.scan.root_event)
    source_event._resolved.set()
    googledns.source = source_event
    manager._emit_event(googledns)
    assert len(event_children) == 0
    assert googledns in results

    # event filtering based on scope_distance
    output_queue = []
    module_queue = []
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor"], output_modules=["json"], config=bbot_config)
    scan1.status = "RUNNING"
    scan1.load_modules()
    manager = scan1.manager
    test_event1 = scan1.make_event("1.2.3.4", source=scan1.root_event)
    test_event1.make_in_scope()
    test_event2 = scan1.make_event("2.3.4.5", source=test_event1)
    test_event3 = scan1.make_event("3.4.5.6", source=test_event2)

    scan1.scope_search_distance = 1
    scan1.scope_report_distance = 0
    assert test_event1.scope_distance == 0
    manager._emit_event(test_event1)
    assert test_event1._internal == False
    assert test_event2.scope_distance == 1
    manager._emit_event(test_event2)
    assert test_event2._internal == True
    manager.events_accepted.clear()
    manager.events_distributed.clear()

    scan1.modules["json"].queue_event = lambda e: output_queue.append(e)
    scan1.modules["ipneighbor"].queue_event = lambda e: module_queue.append(e)

    # in-scope event
    assert test_event1.scope_distance == 0
    manager.distribute_event(test_event1)
    assert hash(test_event1) in manager.events_distributed
    assert test_event1 in module_queue
    assert test_event1 in output_queue
    module_queue.clear()
    output_queue.clear()
    # duplicate event
    manager.distribute_event(test_event1)
    assert test_event1 not in module_queue
    assert test_event1 in output_queue
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 1
    assert test_event2.scope_distance == 1
    manager.distribute_event(test_event2)
    assert test_event2 in module_queue
    assert test_event2 not in output_queue
    assert test_event2._internal == True
    assert test_event2._force_output == False
    assert scan1.modules["json"]._event_precheck(test_event2)[0] == False
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 2
    assert test_event3.scope_distance == 2
    manager.distribute_event(test_event3)
    assert test_event3 not in module_queue
    assert test_event3 not in output_queue
    module_queue.clear()
    output_queue.clear()
    manager.events_distributed.clear()
    # event.scope_distance == 2 and _force_output == True
    test_event3._force_output = True
    assert test_event3.scope_distance == 2
    manager.distribute_event(test_event3)
    assert test_event3 not in module_queue
    assert test_event3 in output_queue
