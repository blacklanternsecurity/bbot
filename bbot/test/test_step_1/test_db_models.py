from datetime import datetime
from zoneinfo import ZoneInfo

from bbot.models.pydantic import Event
from bbot.core.event.base import BaseEvent
from bbot.models.helpers import utc_datetime_validator
from ..bbot_fixtures import *  # noqa


def test_pydantic_models(events, bbot_scanner):
    # test datetime helpers
    now = datetime.now(ZoneInfo("America/New_York"))
    utc_now = utc_datetime_validator(now)
    assert now.timestamp() == utc_now.timestamp()
    now2 = datetime.fromtimestamp(utc_now.timestamp(), ZoneInfo("UTC"))
    assert now2.timestamp() == utc_now.timestamp()
    utc_now2 = utc_datetime_validator(now2)
    assert utc_now2.timestamp() == utc_now.timestamp()

    test_event = Event(**events.ipv4.json())
    assert sorted(test_event.indexed_fields()) == [
        "data",
        "host",
        "id",
        "inserted_at",
        "module",
        "parent",
        "parent_uuid",
        "reverse_host",
        "scan",
        "timestamp",
        "type",
        "uuid",
    ]

    # convert events to pydantic and back, making sure they're exactly the same
    for event in ("ipv4", "http_response", "finding", "storage_bucket"):
        e = getattr(events, event)
        event_json = e.json()
        event_pydantic = Event(**event_json)
        event_pydantic_dict = event_pydantic.model_dump()
        event_reconstituted = BaseEvent.from_json(event_pydantic.model_dump(exclude_none=True))
        assert isinstance(event_json["timestamp"], float)
        assert isinstance(e.timestamp, datetime)
        assert isinstance(event_pydantic.timestamp, float)
        assert not "inserted_at" in event_json
        assert isinstance(event_pydantic_dict["timestamp"], float)
        assert isinstance(event_pydantic_dict["inserted_at"], float)

        event_pydantic_dict = event_pydantic.model_dump(
            exclude_none=True, exclude=["reverse_host", "inserted_at", "archived"]
        )
        assert event_pydantic_dict == event_json
        event_pydantic_dict.pop("scan")
        event_pydantic_dict.pop("module")
        event_pydantic_dict.pop("module_sequence")
        assert event_reconstituted.json() == event_pydantic_dict

    # make sure we can dedupe events by their id
    scan = bbot_scanner()
    event1 = scan.make_event("1.2.3.4", parent=scan.root_event)
    event2 = scan.make_event("1.2.3.4", parent=scan.root_event)
    event3 = scan.make_event("evilcorp.com", parent=scan.root_event)
    event4 = scan.make_event("evilcorp.com", parent=scan.root_event)
    # first two events are IPS
    assert event1.uuid != event2.uuid
    assert event1.id == event2.id
    # second two are DNS
    assert event2.uuid != event3.uuid
    assert event2.id != event3.id
    assert event3.uuid != event4.uuid
    assert event3.id == event4.id

    event_set_bbot = {
        event1,
        event2,
        event3,
        event4,
    }
    assert len(event_set_bbot) == 2
    assert set([e.type for e in event_set_bbot]) == {"IP_ADDRESS", "DNS_NAME"}

    event_set_pydantic = {
        Event(**event1.json()),
        Event(**event2.json()),
        Event(**event3.json()),
        Event(**event4.json()),
    }
    assert len(event_set_pydantic) == 2
    assert set([e.type for e in event_set_pydantic]) == {"IP_ADDRESS", "DNS_NAME"}


def test_event_models_keep_all_json_fields(bbot_scanner):
    scan = bbot_scanner("evilcorp.com", config={"dns": {"minimal": True}})
    dns = scan.make_event("www.evilcorp.com", "DNS_NAME", parent=scan.root_event)
    response = {
        "url": "https://www.evilcorp.com/app.js",
        "method": "GET",
        "status_code": 200,
        "raw_header": "HTTP/1.1 200 OK\r\n\r\n",
        "archive_url": "https://web.archive.org/web/2020/https://www.evilcorp.com/app.js",
    }
    wayback = scan.make_event(response, "HTTP_RESPONSE", parent=dns, tags=["from-wayback"])
    unpacked_data = {k: v for k, v in response.items() if k != "archive_url"}
    unpacked = scan.make_event(unpacked_data, "HTTP_RESPONSE", parent=wayback, tags=["from-wayback"])
    unpacked.reemit_source = "js_unpacker"
    param_data = {
        "host": "www.evilcorp.com",
        "url": "https://www.evilcorp.com/?q=1",
        "name": "q",
        "type": "GETPARAM",
        "original_value": "1",
        "description": "d",
    }
    param = scan.make_event(param_data, "WEB_PARAMETER", parent=dns)

    models = [Event]
    try:
        from bbot.models.sql import Event as SQLEvent

        models.append(SQLEvent)
    except ImportError:  # sqlmodel is only installed alongside the SQL output modules
        pass

    for event in (wayback, unpacked, param):
        event_json = event.json()
        for model in models:
            dumped = model(**event_json).model_dump(exclude_none=True)
            assert not set(event_json) - set(dumped), f"{model.__module__} dropped fields from {event.type}"

    assert Event(**unpacked.json()).reemit_source == "js_unpacker"
    assert Event(**wayback.json()).archive_url == response["archive_url"]
    assert Event(**unpacked.json()).parent_uuid == wayback.uuid
    # a reemitted response's id depends on reemit_source, so it must survive the round trip
    rebuilt = BaseEvent.from_json(Event(**unpacked.json()).model_dump(exclude_none=True))
    assert rebuilt.id == unpacked.id != wayback.id


# TODO: SQL
