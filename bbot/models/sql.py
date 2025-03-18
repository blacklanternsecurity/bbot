# This file contains SQLModel (Pydantic + SQLAlchemy) models for BBOT events, scans, and targets.
# Used by the SQL output modules, but portable for outside use.

import json
import logging
from datetime import datetime
from pydantic import ConfigDict
from typing import List, Optional
from typing_extensions import Annotated
from pydantic.functional_validators import AfterValidator
from sqlmodel import inspect, Column, Field, SQLModel, JSON, String, DateTime as SQLADateTime

from bbot.models.helpers import utc_now_timestamp


log = logging.getLogger("bbot_server.models")


def naive_datetime_validator(d: datetime):
    """
    Converts all dates into UTC, then drops timezone information.

    This is needed to prevent inconsistencies in sqlite, because it is timezone-naive.
    """
    # drop timezone info
    return d.replace(tzinfo=None)


NaiveUTC = Annotated[datetime, AfterValidator(naive_datetime_validator)]


class BBOTBaseModel(SQLModel):
    model_config = ConfigDict(extra="ignore")

    def __init__(self, *args, **kwargs):
        self._validated = None
        super().__init__(*args, **kwargs)

    @property
    def validated(self):
        try:
            if self._validated is None:
                self._validated = self.__class__.model_validate(self)
            return self._validated
        except AttributeError:
            return self

    def to_json(self, **kwargs):
        return json.dumps(self.validated.model_dump(), sort_keys=True, **kwargs)

    @classmethod
    def _pk_column_names(cls):
        return [column.name for column in inspect(cls).primary_key]

    def __hash__(self):
        return hash(self.to_json())

    def __eq__(self, other):
        return hash(self) == hash(other)


### EVENT ###


class Event(BBOTBaseModel, table=True):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.host:
            self.reverse_host = self.host[::-1]

    def get_data(self):
        if self.data is not None:
            return self.data
        return self.data_json

    uuid: str = Field(
        primary_key=True,
        index=True,
        nullable=False,
    )
    id: str = Field(index=True)
    type: str = Field(index=True)
    data: Optional[str] = Field(default=None, index=True)
    data_json: Optional[dict] = Field(default=None, sa_type=JSON)
    host: Optional[str]
    port: Optional[int]
    netloc: Optional[str]
    scope_description: str
    # store the host in reversed form for efficient lookups by domain
    reverse_host: Optional[str] = Field(default="", exclude=True, index=True)
    resolved_hosts: List = Field(default=[], sa_type=JSON)
    dns_children: dict = Field(default={}, sa_type=JSON)
    web_spider_distance: int = 10
    scope_distance: int = Field(default=10, index=True)
    scan: str = Field(index=True)
    timestamp: float = Field(index=True)
    inserted_at: float = Field(default_factory=utc_now_timestamp)
    parent: str = Field(index=True)
    tags: List = Field(default=[], sa_type=JSON)
    module: str = Field(index=True)
    module_sequence: str
    discovery_context: str = ""
    discovery_path: List[str] = Field(default=[], sa_type=JSON)
    parent_chain: List[str] = Field(default=[], sa_type=JSON)


### SCAN ###


class Scan(BBOTBaseModel, table=True):
    id: str = Field(primary_key=True)
    name: str
    status: str
    started_at: NaiveUTC = Field(index=True)
    finished_at: Optional[NaiveUTC] = Field(default=None, sa_column=Column(SQLADateTime, nullable=True, index=True))
    duration_seconds: Optional[float] = Field(default=None)
    duration: Optional[str] = Field(default=None)
    target: dict = Field(sa_type=JSON)
    preset: dict = Field(sa_type=JSON)


### TARGET ###


class Target(BBOTBaseModel, table=True):
    name: str = "Default Target"
    strict_scope: bool = False
    seeds: List = Field(default=[], sa_type=JSON)
    whitelist: List = Field(default=None, sa_type=JSON)
    blacklist: List = Field(default=[], sa_type=JSON)
    hash: str = Field(sa_column=Column("hash", String(length=255), unique=True, primary_key=True, index=True))
    scope_hash: str = Field(sa_column=Column("scope_hash", String(length=255), index=True))
    seed_hash: str = Field(sa_column=Column("seed_hashhash", String(length=255), index=True))
    whitelist_hash: str = Field(sa_column=Column("whitelist_hash", String(length=255), index=True))
    blacklist_hash: str = Field(sa_column=Column("blacklist_hash", String(length=255), index=True))
