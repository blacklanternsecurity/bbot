from bbot.models.pydantic import Event
from ..bbot_fixtures import *  # noqa


def test_pydantic_models(events):

    test_event = Event(**events.ipv4.json())
    assert sorted(test_event._indexed_fields()) == [
        "host",
        "id",
        "module",
        "parent",
        "parent_uuid",
        "reverse_host",
        "scan",
        "timestamp",
        "type",
        "uuid",
    ]

    # events
    for event in ("http_response", "finding", "vulnerability", "ipv4", "storage_bucket"):
        e = getattr(events, event)
        event_json = e.json()
        event_pydantic = Event(**event_json)
        assert event_pydantic.model_dump(exclude_none=True, exclude=["reverse_host"]) == event_json


# TODO: SQL
