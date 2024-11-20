import logging
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Union, Annotated, get_type_hints

from bbot.models.helpers import NaiveUTC, naive_utc_now

log = logging.getLogger("bbot_server.models")


class BBOTBaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    def model_dump(self, preserve_datetime=False, **kwargs):
        ret = super().model_dump(**kwargs)
        if not preserve_datetime:
            for datetime_field in self._datetime_fields():
                if datetime_field in ret:
                    ret[datetime_field] = ret[datetime_field].isoformat()
        return ret

    def __hash__(self):
        return hash(self.to_json())

    def __eq__(self, other):
        return hash(self) == hash(other)

    @classmethod
    def _indexed_fields(cls):
        return sorted(field_name for field_name, field in cls.model_fields.items() if "indexed" in field.metadata)

    @classmethod
    def _get_type_hints(cls):
        """
        Drills down past all the Annotated, Optional, and Union layers to get the underlying type hint
        """
        type_hints = get_type_hints(cls)
        unwrapped_type_hints = {}
        for field_name in cls.model_fields:
            type_hint = type_hints[field_name]
            while 1:
                if getattr(type_hint, "__origin__", None) in (Annotated, Optional, Union):
                    type_hint = type_hint.__args__[0]
                else:
                    break
            unwrapped_type_hints[field_name] = type_hint
        return unwrapped_type_hints

    @classmethod
    def _datetime_fields(cls):
        datetime_fields = []
        for field_name, type_hint in cls._get_type_hints().items():
            if type_hint == datetime:
                datetime_fields.append(field_name)
        return sorted(datetime_fields)


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
    inserted_at: Optional[Annotated[NaiveUTC, "indexed"]] = Field(default_factory=naive_utc_now)
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
