from datetime import datetime, UTC
from zoneinfo import ZoneInfo

from bbot.models.pydantic import Event
from bbot.core.event.base import BaseEvent
from bbot.models.helpers import utc_datetime_validator
from ..bbot_fixtures import *  # noqa


def test_pydantic_models(events):

    # test datetime helpers
    now = datetime.now(ZoneInfo("America/New_York"))
    utc_now = utc_datetime_validator(now)
    assert now.timestamp() == utc_now.timestamp()
    now2 = datetime.fromtimestamp(utc_now.timestamp(), UTC)
    assert now2.timestamp() == utc_now.timestamp()
    utc_now2 = utc_datetime_validator(now2)
    assert utc_now2.timestamp() == utc_now.timestamp()

    test_event = Event(**events.ipv4.json())
    assert sorted(test_event._indexed_fields()) == [
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
    for event in ("ipv4", "http_response", "finding", "vulnerability", "storage_bucket"):
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

        event_pydantic_dict = event_pydantic.model_dump(exclude_none=True, exclude=["reverse_host", "inserted_at"])
        assert event_pydantic_dict == event_json
        event_pydantic_dict.pop("scan")
        event_pydantic_dict.pop("module")
        event_pydantic_dict.pop("module_sequence")
        assert event_reconstituted.json() == event_pydantic_dict


# TODO: SQL
