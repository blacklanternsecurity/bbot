from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_manager(bbot_config, bbot_scanner):
    dns_config = OmegaConf.merge(
        default_config, OmegaConf.create({"dns_resolution": True, "scope_report_distance": 1})
    )

    # test _emit_event
    results = []
    output = []
    event_children = []

    async def results_append(e):
        results.append(e)

    async def output_append(e):
        output.append(e)

    def event_children_append(e):
        event_children.append(e)

    success_callback = lambda e: results.append("success")
    scan1 = bbot_scanner("127.0.0.1", modules=["ipneighbor"], output_modules=["json"], config=dns_config)
    await scan1.load_modules()
    module = scan1.modules["ipneighbor"]
    module.scope_distance_modifier = 0
    module.queue_event = results_append
    output_module = scan1.modules["json"]
    output_module.queue_event = output_append
    scan1.status = "RUNNING"
    manager = scan1.manager
    # manager.distribute_event = lambda e: results.append(e)
    localhost = scan1.make_event("127.0.0.1", source=scan1.root_event, tags=["localhost"])

    class DummyModule1:
        _type = "output"
        suppress_dupes = True

    class DummyModule2:
        _type = "DNS"
        suppress_dupes = True

    class DummyModule3:
        _type = "DNS"
        suppress_dupes = True

    localhost.module = DummyModule1()
    # make sure abort_if works as intended
    await manager._emit_event(localhost, abort_if=lambda e: e.module._type == "output")
    assert len(results) == 0
    manager.events_accepted.clear()
    manager.events_distributed.clear()
    await manager._emit_event(localhost, abort_if=lambda e: e.module._type != "output")
    assert len(results) == 1
    results.clear()
    manager.events_accepted.clear()
    manager.events_distributed.clear()
    # make sure success_callback works as intended
    await manager._emit_event(
        localhost, on_success_callback=success_callback, abort_if=lambda e: e.module._type == "plumbus"
    )
    assert localhost in results
    assert "success" in results
    results.clear()
    # make sure deduplication is working
    localhost2 = scan1.make_event("127.0.0.1", source=scan1.root_event, tags=["localhost2"])
    manager._emit_event(localhost2)
    assert len(results) == 0
    # make sure dns resolution is working
    googledns = scan1.make_event("8.8.8.8", source=scan1.root_event)
    googledns.module = DummyModule2()
    googledns.source = "asdf"
    googledns.set_scope_distance(0)
    manager.queue_event = event_children_append
    await manager._emit_event(googledns)
    assert len(event_children) > 0
    assert googledns in results
    assert googledns in output
    results.clear()
    output.clear()
    event_children.clear()
    # make sure deduplication catches the same event
    await manager._emit_event(googledns)
    assert len(output) == 0
    assert len(results) == 0
    assert len(event_children) == 0
    output.clear()
    event_children.clear()
    # make sure _force_output overrides dup detection
    googledns._force_output = True
    await manager._emit_event(googledns)
    assert googledns in output
    assert len(event_children) == 0
    googledns._force_output = False
    results.clear()
    event_children.clear()
    # same dns event but different source
    source_event = manager.scan.make_event("1.2.3.4", "IP_ADDRESS", source=manager.scan.root_event)
    source_event._resolved.set()
    googledns.source = source_event
    await manager._emit_event(googledns)
    assert len(event_children) == 0
    assert googledns in output

    # error catching
    msg = "Ignore this error, it belongs here"
    exceptions = (Exception(msg), KeyboardInterrupt(msg), BrokenPipeError(msg))
    for e in exceptions:
        with manager.scan.catch():
            raise e


@pytest.mark.asyncio
async def test_scope_distance(bbot_scanner, bbot_config):
    # event filtering based on scope_distance
    scan1 = bbot_scanner(
        "127.0.0.1", "evilcorp.com", modules=["ipneighbor"], output_modules=["json"], config=bbot_config
    )
    scan1.status = "RUNNING"
    await scan1.load_modules()
    module = scan1.modules["ipneighbor"]
    module_queue = module.incoming_event_queue._queue
    output_module = scan1.modules["json"]
    output_queue = output_module.incoming_event_queue._queue
    manager = scan1.manager
    test_event1 = scan1.make_event("127.0.0.1", source=scan1.root_event)

    assert scan1.scope_search_distance == 0
    assert scan1.scope_report_distance == 0
    assert module.scope_distance_modifier == 1

    # test _emit_event() with scope_distance == 0
    await manager._emit_event(test_event1)
    assert test_event1.scope_distance == 0
    assert test_event1._internal == False
    assert test_event1 in output_queue
    assert test_event1 in module_queue

    test_event2 = scan1.make_event("2.3.4.5", source=test_event1)
    test_event3 = scan1.make_event("3.4.5.6", source=test_event2)
    test_event4 = scan1.make_event("4.5.6.7", source=test_event2)
    test_event4._force_output = True
    dns_event = scan1.make_event("evilcorp.com", source=scan1.root_event)

    # non-watched event type
    await manager._emit_event(dns_event)
    assert dns_event.scope_distance == 0
    assert dns_event in output_queue
    assert dns_event not in module_queue

    # test _emit_event() with scope_distance == 1
    assert test_event2.scope_distance == 1
    await manager._emit_event(test_event2)
    assert test_event2.scope_distance == 1
    assert test_event2._internal == True
    assert test_event2 not in output_queue
    assert test_event2 in module_queue
    valid, reason = await module._event_postcheck(test_event2)
    assert valid

    # test _emit_event() with scope_distance == 2
    assert test_event3.scope_distance == 2
    await manager._emit_event(test_event3)
    assert test_event3.scope_distance == 2
    assert test_event3._internal == True
    assert test_event3 not in output_queue
    assert test_event3 in module_queue
    valid, reason = await module._event_postcheck(test_event3)
    assert not valid
    assert reason.startswith("its scope_distance (2) exceeds the maximum allowed by the scan")

    # test _emit_event() with scope_distance == 2 and _force_output == True
    assert test_event4.scope_distance == 2
    await manager._emit_event(test_event4)
    assert test_event4.scope_distance == 2
    assert test_event4._internal == True
    assert test_event4._force_output == True
    assert test_event4 in output_queue
    assert test_event4 in module_queue
    valid, reason = await module._event_postcheck(test_event4)
    assert not valid
    assert reason.startswith("its scope_distance (2) exceeds the maximum allowed by the scan")

    # test _always_emit == True
    geoevent = scan1.make_event("USA", "GEOLOCATION", source=test_event3)
    assert geoevent.scope_distance == 3
    assert geoevent.always_emit == True
    assert geoevent._force_output == False
    await manager._emit_event(geoevent)
    assert geoevent._force_output == True
    assert geoevent in output_queue
    assert geoevent not in module_queue

    # test always_emit tag
    affiliate_event = scan1.make_event("5.6.7.8", source=test_event3, tags="affiliate")
    assert "affiliate" in affiliate_event.tags
    assert "affiliate" in affiliate_event._always_emit_tags
    assert affiliate_event.scope_distance == 3
    assert affiliate_event._always_emit == False
    assert affiliate_event.always_emit == True
    assert affiliate_event._force_output == False
    await manager._emit_event(affiliate_event)
    assert affiliate_event._force_output == True
    assert affiliate_event in output_queue
    assert affiliate_event in module_queue
    valid, reason = await module._event_postcheck(affiliate_event)
    assert not valid
    assert reason.startswith("its scope_distance (3) exceeds the maximum allowed by the scan")
