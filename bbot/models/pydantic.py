import json
import logging
from datetime import datetime
from typing import Optional, List, Union, Annotated
from pydantic import BaseModel, ConfigDict, field_serializer

from bbot.models.helpers import NaiveUTC, naive_datetime_validator

log = logging.getLogger("bbot_server.models")


class BBOTBaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    def to_json(self, **kwargs):
        return json.dumps(self.model_dump(), sort_keys=True, **kwargs)

    def __hash__(self):
        return hash(self.to_json())

    def __eq__(self, other):
        return hash(self) == hash(other)


### EVENT ###

class Event(BBOTBaseModel):
    uuid: Annotated[str, "indexed", "unique"]
    id: Annotated[str, "indexed"]
    type: Annotated[str, "indexed"]
    scope_description: str
    data: Union[dict, str]
    host: Annotated[Optional[str], "indexed"] = None
    port: Optional[int] = None
    netloc: Optional[str] = None
    # we store the host in reverse to allow for instant subdomain queries
    # this works because indexes are left-anchored, but we need to search starting from the right side
    reverse_host: Annotated[Optional[str], "indexed"] = ""
    resolved_hosts: Union[List, None] = None
    dns_children: Union[dict, None] = None
    web_spider_distance: int = 10
    scope_distance: int = 10
    scan: Annotated[str, "indexed"]
    timestamp: Annotated[NaiveUTC, "indexed"]
    parent: Annotated[str, "indexed"]
    parent_uuid: Annotated[str, "indexed"]
    tags: List = []
    module: Annotated[Optional[str], "indexed"] = None
    module_sequence: Optional[str] = None
    discovery_context: str = ""
    discovery_path: List[str] = []
    parent_chain: List[str] = []

    def __init__(self, **data):
        super().__init__(**data)
        if self.host:
            self.reverse_host = self.host[::-1]

    @staticmethod
    def _get_data(data, type):
        if isinstance(data, dict) and list(data) == [type]:
            return data[type]
        return data

    @classmethod
    def _indexed_fields(cls):
        return sorted(
            field_name for field_name, field in cls.model_fields.items() if "indexed" in field.metadata
        )

    @field_serializer("timestamp")
    def serialize_timestamp(self, timestamp: datetime, _info):
        return naive_datetime_validator(timestamp).isoformat()


### SCAN ###

class Scan(BBOTBaseModel):
    id: Annotated[str, "indexed", "unique"]
    name: str
    status: Annotated[str, "indexed"]
    started_at: Annotated[NaiveUTC, "indexed"]
    finished_at: Optional[Annotated[NaiveUTC, "indexed"]] = None
    duration_seconds: Optional[float] = None
    duration: Optional[str] = None
    target: dict
    preset: dict

    @classmethod
    def from_scan(cls, scan):
        return cls(
            id=scan.id,
            name=scan.name,
            status=scan.status,
            started_at=scan.started_at,
        )


### TARGET ###

class Target(BBOTBaseModel):
    name: str = "Default Target"
    strict_scope: bool = False
    seeds: List = []
    whitelist: List = []
    blacklist: List = []
    hash: Annotated[str, "indexed", "unique"]
    scope_hash: Annotated[str, "indexed"]
    seed_hash: Annotated[str, "indexed"]
    whitelist_hash: Annotated[str, "indexed"]
    blacklist_hash: Annotated[str, "indexed"]
