from datetime import datetime

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
        event_pydantic_dict = event_pydantic.to_json()
        event_pydantic_dict_datetime = event_pydantic.to_json(preserve_datetime=True)
        assert isinstance(event_pydantic_dict["timestamp"], str)
        assert isinstance(event_pydantic_dict["inserted_at"], str)
        assert isinstance(event_pydantic_dict_datetime["timestamp"], datetime)
        assert isinstance(event_pydantic_dict_datetime["inserted_at"], datetime)
        assert event_pydantic.model_dump(exclude_none=True, exclude=["reverse_host"]) == event_json


# TODO: SQL
